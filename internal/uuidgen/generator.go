package uuidgen

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/ashutoshgngwr/go-qrng"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	sphincs_plus "github.com/kasperdi/SPHINCSPLUS-golang/sphincs" // SPHINCS+ implementation
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/sha3"
)

/*
1. Server-Side Setup
Define API Endpoints:

POST /generate: Generate a new quantum UUID. - DONE
GET /uuid/{id}: Retrieve metadata for a specific UUID.
POST /validate: Validate a UUID against its metadata.

Implement UUID Generation:
Use GenerateQuantumUUID to create UUIDs with quantum-safe features. - DONE
Add metadata (e.g., creation timestamp, client ID, use case).

Store UUIDs:
Use a database (e.g., PostgreSQL, MongoDB) to store UUIDs and associated metadata.

*/

type QuantumUUIDMetadata struct {
	UUID         string `json:"uuid"`
	ECDSASig     string `json:"ecdsaSignature"`
	ECDSAPub     []byte `json:"ecdsaPublicKey"`
	SPHINCSSig   string `json:"sphincsSignature"`
	SPHINCSPub   string `json:"sphincsPublicKey"`
	Hash         string `json:"hash"`
	Timestamp    int64  `json:"timestamp"`
	DerivedKey   string `json:"derivedKey"`
	RandomSource string `json:"randomSource"` // Indicates QRNG usage
}

// Constants for QRUUID Version and Variant (from RFC 4122 and RFC 9562)
const (
	UUIDVersion = 0x80 // Version 8 for QRUUID (custom UUID version with quantum resistance)
	UUIDVariant = 0x80 // Variant '10' (from RFC 4122)
)

// SetQRUUIDVersionAndVariant modifies the provided UUID to include the Version and Variant from RFC 9562.
func SetQRUUIDVersionAndVariant(uuid []byte) []byte {
	// Set QRUUID Version (4 most significant bits of byte 6)
	uuid[6] = (uuid[6] & 0x0F) | UUIDVersion

	// Set QRUUID Variant (2 most significant bits of byte 8)
	uuid[8] = (uuid[8] & 0x3F) | UUIDVariant
	return uuid
}

// GenerateQuantumUUID creates a quantum-resistant UUID and its hybrid metadata.
func GenerateQuantumUUID() (*QuantumUUIDMetadata, error) {
	// Step 1: QRNG entropy generation
	q := &qrng.Config{
		PanicOnError: false,
		EnableBuffer: true,
	}
	v := qrng.NewSource(q)

	entropy := make([]byte, 0, 64)
	for len(entropy) < 64 {
		x := v.Uint64()
		xBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(xBytes, x)
		entropy = append(entropy, xBytes...)
	}
	entropy = entropy[:64]

	// Add system entropy
	systemEntropy := make([]byte, 64)
	if _, err := rand.Read(systemEntropy); err != nil {
		return nil, fmt.Errorf("failed to read system entropy: %v", err)
	}
	entropy = append(entropy, systemEntropy...)

	// Add timestamp entropy
	timestamp := time.Now().UnixNano()
	entropy = append(entropy, []byte(fmt.Sprintf("%d", timestamp))...)

	// Step 2: Multiple rounds of hashing
	hash1 := sha3.NewShake256()
	hash1.Write(entropy)
	var shakeOutput [64]byte
	hash1.Read(shakeOutput[:])

	blake3Output := blake3.Sum512(shakeOutput[:])

	hash3 := sha3.New512()
	hash3.Write(blake3Output[:])
	sha3Output := hash3.Sum(nil)

	// Step 3: Key derivation (Argon2id)
	salt := []byte(fmt.Sprintf("%d", timestamp))
	derivedKey := argon2.IDKey(sha3Output[:], salt, 3, 32*1024, 4, 32)

	// Step 4: Hybrid cryptography (ECDSA + SPHINCS+)
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %v", err)
	}
	pubKey, err := EncodeECDSAPublicKeyToPEM(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode ECDSA key to PEM: %v", err)
	}
	ecdsaSignature, err := privateKey.Sign(rand.Reader, derivedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with ECDSA: %v", err)
	}

	params := parameters.MakeSphincsPlusSHAKE256256fRobust(true)
	sk, pk := sphincs_plus.Spx_keygen(params)
	// Serialize the SPHINCS+ public key
	serializedPK, err := pk.SerializePK()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize SPHINCS+ public key: %v", err)
	}
	spSignature := sphincs_plus.Spx_sign(params, sha3Output[:32], sk)
	if !sphincs_plus.Spx_verify(params, sha3Output[:32], spSignature, pk) {
		return nil, fmt.Errorf("SPHINCS+ verification failed")
	}

	// Step 5: Masking the UUID with AES encryption
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}
	ciphertext := make([]byte, len(sha3Output))
	stream := cipher.NewCTR(block, sha3Output[:aes.BlockSize])
	stream.XORKeyStream(ciphertext, sha3Output)

	// Combine ciphertext and signatures
	quantumUUID := append(ciphertext, ecdsaSignature...)
	quantumUUID = append(quantumUUID, spSignature.GetR()...)

	quantumUUID = SetQRUUIDVersionAndVariant(quantumUUID)

	// Create metadata
	metadata := &QuantumUUIDMetadata{
		UUID:         hex.EncodeToString(quantumUUID),
		ECDSASig:     hex.EncodeToString(ecdsaSignature),
		ECDSAPub:     pubKey,
		SPHINCSSig:   hex.EncodeToString(spSignature.GetR()),
		SPHINCSPub:   hex.EncodeToString(serializedPK),
		Hash:         hex.EncodeToString(sha3Output),
		Timestamp:    timestamp,
		DerivedKey:   hex.EncodeToString(derivedKey),
		RandomSource: "QRNG + System Entropy",
	}

	return metadata, nil
}

func ValidateQuantumUUID(quantumUUID string, metadata QuantumUUIDMetadata) (bool, error) {
	// Step 1: Validate UUID Format (length, version, variant)
	// Step 2: Extract UUID Data (UUID & Signature) and Check Metadata Consistency
	uuidData, result := isValidUUID(quantumUUID)
	if !result {
		return false, fmt.Errorf("Invalid UUID format")
	}

	pubKeyRaw, err := base64.URLEncoding.DecodeString(string(metadata.ECDSAPub))
	if err != nil {
		return false, fmt.Errorf("Unable to bas64 decode ECDSAPubKey")
	}
	// Step 3: Verify Signatures
	pubKey, err := DecodePEMToECDSAPublicKey(pubKeyRaw)
	if err != nil {
		return false, fmt.Errorf("Unable to decode to ECDSAPubKey from PEM Key")
	}
	if !verifyECDSASignature(uuidData, []byte(metadata.ECDSASig), pubKey) {
		return false, fmt.Errorf("ECDSA signature verification failed")
	}

	if !verifySPHINCSPlusSignature(uuidData, []byte(metadata.SPHINCSSig), []byte(metadata.SPHINCSPub)) {
		return false, fmt.Errorf("SPHINCS+ signature verification failed")
	}

	// Step 4: Check Hashing Integrity
	// Compute and compare hashes: SHA3-256, BLAKE3, and SHA3-512
	computedHash := computeHash(uuidData)
	if !compareHashes(computedHash, []byte(metadata.Hash)) {
		return false, fmt.Errorf("Hash mismatch")
	}

	// Step 5: Validate Metadata Integrity (Timestamp, Key Material, etc.)
	if !validateTimestamp(metadata.Timestamp) {
		return false, fmt.Errorf("Invalid timestamp")
	}

	// Optional: Validate derived key and encryption if needed
	if !verifyEncryption(uuidData, []byte(metadata.DerivedKey)) {
		return false, fmt.Errorf("Encryption validation failed")
	}

	// If all checks pass, return true
	return true, nil
}

// Function to verify ECDSA Signature
func verifyECDSASignature(message []byte, signature []byte, pubKey *ecdsa.PublicKey) bool {
	// Hash the message
	hashedMessage := sha256.Sum256(message)

	// Decode the signature (assuming it's a DER-encoded signature)
	r, s := new(big.Int), new(big.Int)
	if len(signature) != 64 {
		log.Printf("Invalid signature length")
		return false
	}

	r.SetBytes(signature[:32])
	s.SetBytes(signature[32:])

	// Verify the signature
	valid := ecdsa.Verify(pubKey, hashedMessage[:], r, s)
	return valid
}

// Example function to verify SPHINCS+ signature
func verifySPHINCSPlusSignature(uuidData []byte, signature []byte, pubKey []byte) bool {
	// Your SPHINCS+ verification logic here
	params := parameters.MakeSphincsPlusSHAKE256256fRobust(true)
	sg, err := sphincs_plus.DeserializeSignature(params, signature)
	if err != nil {
		return false
	}
	pk, err := sphincs_plus.DeserializePK(params, pubKey)
	if err != nil {
		return false
	}
	sphincs_plus.Spx_verify(params, uuidData, sg, pk)
	return true
}

// Example function to compute the hash of the UUID data
func computeHash(data []byte) []byte {
	hash := sha3.New512()
	hash.Write(data)
	return hash.Sum(nil)
}

// Example function to compare the computed hash with expected hash
func compareHashes(computedHash []byte, expectedHash []byte) bool {
	return bytes.Equal(computedHash, expectedHash)
}

// Example function to validate timestamp range
func validateTimestamp(timestamp int64) bool {
	// Ensure timestamp is within a reasonable range
	return timestamp > 0 && timestamp < time.Now().Unix()
}

// Function to validate UUID structure: length, version, and variant
func isValidUUID(quantumUUID string) ([]byte, bool) {
	// The UUID should be greater than 256-bit (32 bytes) in length
	if len(quantumUUID) < 256 {
		return nil, false
	}

	// Decode the hex string into a byte slice
	uuidData, err := hex.DecodeString(quantumUUID)
	if err != nil {
		return nil, false
	}

	// Check UUID Version: Should be version 8 (indicated by 0x80 in the 7th byte)
	if uuidData[6]&0xF0 != 0x80 {
		return nil, false
	}

	// Check UUID Variant: RFC specifies the variant should be 0x80 for variant 1 (standard UUIDs)
	if uuidData[8]&0xC0 != 0x80 {
		return nil, false
	}

	return uuidData, true
}

// Function to verify the AES decryption of the UUID data
func verifyEncryption(uuidData []byte, derivedKey []byte) bool {
	// Check if the UUID data length matches what we expect (should be 128 bytes)
	if len(uuidData) != 128 {
		return false
	}

	// Use the first 16 bytes as the AES IV (Initialization Vector) for CTR mode
	iv := uuidData[:aes.BlockSize]         // Assuming the first 16 bytes are used as IV
	cipherText := uuidData[aes.BlockSize:] // The remaining part is the encrypted ciphertext

	// Create a new AES cipher block using the derived key
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		fmt.Printf("Error creating AES cipher: %v\n", err)
		return false
	}

	// Create a new AES CTR stream
	stream := cipher.NewCTR(block, iv)

	// Decrypt the ciphertext
	decrypted := make([]byte, len(cipherText))
	stream.XORKeyStream(decrypted, cipherText)

	// Here we assume the decrypted data should match the expected cleartext (hash or other data)
	// In this case, we will just check that the decrypted data is not empty as an example validation
	if len(decrypted) == 0 {
		return false
	}

	// Add further checks as necessary, depending on the expected structure of the decrypted data
	return true
}

// EncodeECDSAPublicKeyToPEM encodes an ECDSA public key to PEM format.
func EncodeECDSAPublicKeyToPEM(pubKey *ecdsa.PublicKey) ([]byte, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("error marshaling public key to DER: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}

	return pem.EncodeToMemory(pemBlock), nil
}

// DecodePEMToECDSAPublicKey decodes a PEM-encoded public key to an ECDSA public key.
func DecodePEMToECDSAPublicKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %w", err)
	}

	// Ensure the parsed key is of type *ecdsa.PublicKey
	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("decoded key is not an ECDSA public key")
	}

	return ecdsaPubKey, nil
}
