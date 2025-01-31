package db

import (
	"pq-uuid.internal/internal/uuidgen"
)

// DBInterface defines methods for interacting with a database
type DBInterface interface {
	// Save stores the full metadata (including secure fields)
	Save(metadata *uuidgen.QuantumUUIDMetadata) error

	// Get retrieves the metadata by UUID (does not include secure fields like DerivedKey)
	Get(uuid string) (*uuidgen.QuantumUUIDMetadata, error)

	// GetPublicData retrieves only the publicly shareable data
	GetPublicData(uuid string) (*uuidgen.QuantumUUIDMetadata, error)

	// Delete removes the metadata from the database
	Delete(uuid string) error
}
