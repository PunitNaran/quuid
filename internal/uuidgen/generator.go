package uuidgen

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
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
	ECDSAPub     []byte `json:"ecdsaPublicKey"`
	SPHINCSPub   string `json:"sphincsPublicKey"`
	Timestamp    int64  `json:"timestamp"`
	RandomSource string `json:"randomSource,omitempty"` // Indicates QRNG usage

	// Private fields (not shared in the API response)
	ECDSASig   string `json:"ecdsaSignature,omitempty"`
	SPHINCSSig string `json:"sphincsSignature,omitempty"`
	Hash       string `json:"hash,omitempty"`
	DerivedKey string `json:"derivedKey,omitempty"`
	Entropy    string `json:"entropy,omitempty"`
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
	// Uses the Australian National University's Quantum Random Number Generator
	// This could be changed later to a In-House QRNG
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
	derivedKey := argon2.IDKey(sha3Output[:], salt, 3, 32*1024, 4, 48)

	// Step 4: Hybrid cryptography (ECDSA + SPHINCS+)
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %v", err)
	}
	pubKey, err := EncodeECDSAPublicKeyToPEM(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode ECDSA key to PEM: %v", err)
	}

	ecdsaSignature, err := ecdsa.SignASN1(rand.Reader, privateKey, derivedKey[:])
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
	aesKey := derivedKey[:32]  // First 32 bytes for AES key
	aesIV := derivedKey[32:48] // Last 16 bytes for IV

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	ciphertext := make([]byte, len(sha3Output))
	stream := cipher.NewCTR(block, aesIV)
	stream.XORKeyStream(ciphertext, sha3Output)

	// Combine ciphertext and signatures
	quantumUUID := append(ciphertext, ecdsaSignature...)
	quantumUUID = append(quantumUUID, spSignature.GetR()...)

	quantumUUID = SetQRUUIDVersionAndVariant(quantumUUID)

	sig, err := spSignature.SerializeSignature()
	if err != nil {
		return nil, fmt.Errorf("failed to create SPHINCS Serialize Signature: %v", err)
	}
	// Create metadata
	metadata := &QuantumUUIDMetadata{
		UUID:         hex.EncodeToString(quantumUUID),
		ECDSASig:     hex.EncodeToString(ecdsaSignature),
		ECDSAPub:     pubKey,
		SPHINCSSig:   hex.EncodeToString(sig),
		SPHINCSPub:   hex.EncodeToString(serializedPK),
		Hash:         hex.EncodeToString(sha3Output),
		Timestamp:    timestamp,
		DerivedKey:   hex.EncodeToString(derivedKey),
		RandomSource: "QRNG + System Entropy",
		Entropy:      hex.EncodeToString(entropy),
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

	// Step 3: Verify Signatures
	pubKey, err := DecodePEMToECDSAPublicKey(metadata.ECDSAPub)
	if err != nil {
		return false, fmt.Errorf("Unable to decode to ECDSAPubKey from PEM Key")
	}
	signiture, err := hex.DecodeString(metadata.ECDSASig)
	if err != nil {
		return false, fmt.Errorf("Unable to decode to ECDSASig")
	}

	hashed, err := hex.DecodeString(metadata.DerivedKey)
	if err != nil {
		return false, fmt.Errorf("Derived key decode failed")
	}
	if !verifyECDSASignature(hashed, signiture, pubKey) {
		return false, fmt.Errorf("ECDSA signature verification failed")
	}

	if !verifySPHINCSPlusSignature(metadata.Hash, metadata.SPHINCSSig, metadata.SPHINCSPub) {
		return false, fmt.Errorf("SPHINCS+ signature verification failed")
	}

	// Step 4: Recompute the hash using stored entropy
	entropy, err := hex.DecodeString(metadata.Entropy)
	if err != nil {
		return false, fmt.Errorf("Failed to decode stored entropy: %v", err)
	}

	hash1 := sha3.NewShake256()
	hash1.Write(entropy)
	var shakeOutput [64]byte
	hash1.Read(shakeOutput[:])

	blake3Output := blake3.Sum512(shakeOutput[:])

	hash3 := sha3.New512()
	hash3.Write(blake3Output[:])
	sha3Output := hash3.Sum(nil)

	// Step 5: Check Hash Integrity
	computedHash := sha3Output

	computedHashFromMetadata, err := hex.DecodeString(metadata.Hash)
	if err != nil {
		return false, fmt.Errorf("failed to decode stored hash from metadata: %v", err)
	}

	if !compareHashes(computedHash, computedHashFromMetadata) {
		return false, fmt.Errorf("Hash mismatch")
	}

	// Step 6: Validate Metadata Integrity (Timestamp, Key Material, etc.)
	if !validateTimestamp(metadata.Timestamp) {
		return false, fmt.Errorf("Invalid timestamp")
	}

	// Step 7: Validate Encryption (AES + Derived Key)
	// Call verifyEncryption with expectedHash (sha3Output) from metadata
	if !verifyEncryption(uuidData[:64], hashed, computedHash) {
		return false, fmt.Errorf("Encryption validation failed")
	}

	// If all checks pass, return true
	return true, nil
}

// ECDSA Signature structure for ASN.1 DER decoding
type ecdsaSignature struct {
	R, S *big.Int
}

// verifyECDSASignature verifies an ECDSA P-384 signature.
func verifyECDSASignature(derivedKey []byte, signature []byte, pubKey *ecdsa.PublicKey) bool {
	// Step 1: Decode the ASN.1 encoded signature
	var sig ecdsaSignature
	if _, err := asn1.Unmarshal(signature, &sig); err != nil {
		fmt.Println("Error: Failed to decode ASN.1 signature:", err)
		return false
	}

	// Step 2: Verify the signature
	isValid := ecdsa.Verify(pubKey, derivedKey[:], sig.R, sig.S)
	fmt.Println("ECDSA Verification Result:", isValid)
	return isValid
}

// Example function to verify SPHINCS+ signature
func verifySPHINCSPlusSignature(hashHex string, signature string, pubKey string) bool {
	// Your SPHINCS+ verification logic here
	params := parameters.MakeSphincsPlusSHAKE256256fRobust(true)
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	sg, err := sphincs_plus.DeserializeSignature(params, sig)
	if err != nil {
		return false
	}
	key, err := hex.DecodeString(pubKey)
	if err != nil {
		return false
	}
	pk, err := sphincs_plus.DeserializePK(params, key)
	if err != nil {
		return false
	}

	// Step 2: decode the hashHex
	hash, err := hex.DecodeString(hashHex)
	if err != nil {
		return false
	}
	sphincs_plus.Spx_verify(params, hash, sg, pk)
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
	v := timestamp > 1738276354042445800 && timestamp < time.Now().UnixNano()
	return v
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
func verifyEncryption(encryptedUUID, derivedKey []byte, expectedHash []byte) bool {
	// Check if the UUID data length matches what we expect (should be 64 bytes)
	if len(encryptedUUID) != 64 {
		return false
	}

	// Extract AES key (first 32 bytes) and IV (next 16 bytes)
	aesKey := derivedKey[:32]
	aesIV := derivedKey[32:48]

	// Create AES cipher block with the provided key
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return false
	}

	// Create the AES CTR stream cipher
	stream := cipher.NewCTR(block, aesIV)

	// Decrypt the UUID data using AES CTR mode
	decryptedUUID := make([]byte, len(expectedHash))
	stream.XORKeyStream(decryptedUUID, expectedHash)

	decryptedUUID = SetQRUUIDVersionAndVariant(decryptedUUID)
	// At this point, decryptedUUID should match the expected sha3Output
	// Compare the decrypted result with the expected hash (sha3Output)
	return compareHashes(decryptedUUID, encryptedUUID)
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
