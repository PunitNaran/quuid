package uuidgen

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGenerateQuantumUUID(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"ValidUUID", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test GenerateQuantumUUID
			v, err := GenerateQuantumUUID()
			if tt.wantErr {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Unexpected error occurred")
				assert.NotEmpty(t, v, "Generated UUID is empty")

				// Validate UUID structure
				err = validateUUIDStructure(v.UUID)
				assert.NoError(t, err, "Generated UUID has invalid structure: %v", err)
			}
		})
	}
}

// validateUUIDStructure validates that a UUID string conforms to the expected format.
func validateUUIDStructure(uuid string) error {
	bytes, err := hex.DecodeString(uuid)
	if err != nil {
		return err
	}
	if len(bytes) < 128 { // Adjust this length if necessary based on UUID design
		return fmt.Errorf("invalid UUID length: got %d, expected 256 bytes", len(bytes))
	}

	// Check version and variant bits
	if (bytes[6]&0xF0)>>4 != 8 { // Version 8 (binary: 1000)
		return fmt.Errorf("invalid version: got %d, expected 8", (bytes[6]&0xF0)>>4)
	}
	if (bytes[8]&0xC0)>>6 != 2 { // Variant (binary: 10)
		return fmt.Errorf("invalid variant: got %d, expected 2", (bytes[8]&0xC0)>>6)
	}

	return nil
}

func TestValidateQuantumUUID(t *testing.T) {

	// Define a valid QuantumUUIDMetadata
	validMetadata := QuantumUUIDMetadata{
		UUID:         "d2dd39da7d3b8ac9bd928e7c33db572cc307481951ae45ea443ce8a6318acd791ab44ed084a05cd18766fa15bd970451605d481afa47e7631576ed006e05d9d4306402307760a2b18eab14ff407f4677ee632f3b5200ed954e95cacef738bf72bcbd64f03c5550bc006af0ab2870fa64b19fe6b3023063dbd6d1878416bce783c81107efebe9c3abd8ed02a49df260819563464a19a2a36977bcf784567d8943ba8a774077f7852ac9181c6038cd48a97d9101150a4ccd0a5daae33b49793ee77eb4a7fd1aaf",
		ECDSASig:     "306402307760a2b18eab14ff407f4677ee632f3b5200ed954e95cacef738bf72bcbd64f03c5550bc006af0ab2870fa64b19fe6b3023063dbd6d1878416bce783c81107efebe9c3abd8ed02a49df260819563464a19a2a36977bcf784567d8943ba8a774077f7",
		ECDSAPub:     []byte("LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUUvVlFPMHAzTEJSQU83S0ZtQ2xSeEU2T0g4SXRMcEJPMgpYZFQ3WVJNQ0J3WGFaOEp6Q01kNzdQbVpmMGtlc2pPVXk3OVBUWUJaYVZFN0YxVVllc1puR0l1RlM1MGRXUXMzCmF2WlR5SUJldnBNU3JmMFl4Nk4vQUNLaWNHc3ZIcDRqCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo="),
		SPHINCSSig:   "852ac9181c6038cd48a97d9101150a4ccd0a5daae33b49793ee77eb4a7fd1aaf",
		SPHINCSPub:   "1746e7d07195c77fd91ae28403c9df458421bfadd6cc7b7196487abb32c2eae0cf6afa12d2b14397735c5f38dfe744dffb94158a13f721c8b1b985d59c8f7a79",
		Hash:         "0ca8d717c37cfe14a2fa5b355f79241a5d9b79e606c2f855a9dcf3b8ee878e456dfd0a3c394b46afc0109d426d66847dd8dd6647c0ee9430732cef9a45821f37",
		Timestamp:    time.Now().UnixNano(),
		DerivedKey:   "2269f0adaca2a49495eef49fbd0908af7f9ccf75f5a5b993dd748ef017cbef53",
		RandomSource: "QRNG + System Entropy",
	}

	tests := []struct {
		name        string
		quantumUUID string
		metadata    QuantumUUIDMetadata
		wantValid   bool
		wantErr     bool
	}{
		{
			name:        "ValidUUID",
			quantumUUID: validMetadata.UUID,
			metadata:    validMetadata,
			wantValid:   true,
			wantErr:     false,
		}, /*
			{
				name:        "InvalidUUIDFormat",
				quantumUUID: "invalidUUID",
				metadata:    validMetadata,
				wantValid:   false,
				wantErr:     true,
			},
			{
				name:        "ECDSASignatureMismatch",
				quantumUUID: validMetadata.UUID,
				metadata: func() QuantumUUIDMetadata {
					invalidMetadata := validMetadata
					invalidMetadata.ECDSASig = "invalidSignature"
					return invalidMetadata
				}(),
				wantValid: false,
				wantErr:   true,
			},
			{
				name:        "HashMismatch",
				quantumUUID: validMetadata.UUID,
				metadata: func() QuantumUUIDMetadata {
					invalidMetadata := validMetadata
					invalidMetadata.Hash = "incorrectHash"
					return invalidMetadata
				}(),
				wantValid: false,
				wantErr:   true,
			},
			{
				name:        "InvalidTimestamp",
				quantumUUID: validMetadata.UUID,
				metadata: func() QuantumUUIDMetadata {
					invalidMetadata := validMetadata
					invalidMetadata.Timestamp = 0 // Simulate an invalid timestamp
					return invalidMetadata
				}(),
				wantValid: false,
				wantErr:   true,
			},*/
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := ValidateQuantumUUID(tt.quantumUUID, tt.metadata)

			if tt.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.False(t, valid, "Expected UUID to be invalid")
			} else {
				assert.NoError(t, err, "Unexpected error occurred")
				assert.True(t, valid, "Expected UUID to be valid")
			}
		})
	}
}
