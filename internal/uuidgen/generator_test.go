package uuidgen

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

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

				store, _ := json.Marshal(v)
				os.WriteFile("data.json", store, 0644)
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
	v, _ := os.ReadFile("./data.json")
	validMetadata := QuantumUUIDMetadata{}
	json.Unmarshal(v, &validMetadata)
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
		},
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
		},
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
