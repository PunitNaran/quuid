package db

import (
	"errors"
	"sync"

	"pq-uuid.internal/internal/uuidgen"
)

// InMemoryDB is a simple in-memory database for testing purposes
type InMemoryDB struct {
	data map[string]*uuidgen.QuantumUUIDMetadata
	mu   sync.Mutex
}

// NewInMemoryDB creates a new instance of the in-memory database
func NewInMemoryDB() *InMemoryDB {
	return &InMemoryDB{
		data: make(map[string]*uuidgen.QuantumUUIDMetadata),
	}
}

// Save stores the full metadata in memory
func (db *InMemoryDB) Save(metadata *uuidgen.QuantumUUIDMetadata) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if _, exists := db.data[metadata.UUID]; exists {
		return errors.New("UUID already exists")
	}
	db.data[metadata.UUID] = metadata
	return nil
}

// Get retrieves the full metadata by UUID
func (db *InMemoryDB) Get(uuid string) (*uuidgen.QuantumUUIDMetadata, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	metadata, exists := db.data[uuid]
	if !exists {
		return nil, errors.New("UUID not found")
	}
	return metadata, nil
}

// GetPublicData retrieves only the publicly shareable data (excluding sensitive fields like DerivedKey)
func (db *InMemoryDB) GetPublicData(uuid string) (*uuidgen.QuantumUUIDMetadata, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	metadata, exists := db.data[uuid]
	if !exists {
		return nil, errors.New("UUID not found")
	}

	// Create a copy of the metadata with sensitive fields omitted
	publicData := *metadata
	publicData.DerivedKey = "" // Remove DerivedKey
	publicData.ECDSAPub = nil  // Remove ECDSAPub
	publicData.SPHINCSPub = "" // Remove SPHINCSPub
	publicData.Entropy = ""    // Optionally, remove Entropy if needed

	return &publicData, nil
}

// Delete removes the metadata from memory
func (db *InMemoryDB) Delete(uuid string) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if _, exists := db.data[uuid]; !exists {
		return errors.New("UUID not found")
	}
	delete(db.data, uuid)
	return nil
}
