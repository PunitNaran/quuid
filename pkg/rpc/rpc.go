package rpc

import (
	"context"
	"fmt"

	"github.com/rs/zerolog/log"
	"pq-uuid.internal/internal/db"
	"pq-uuid.internal/internal/uuidgen"
)

// Server implements the UUIDGeneration gRPC service
type Server struct {
	dbStore db.DBInterface
}

// UUIDRequest and UUIDResponse are the request and response types for gRPC
type UUIDRequest struct{}
type UUIDResponse struct {
	Uuid string
}

// GenerateUUID generates and returns a quantum-resistant UUID
// WORK IN PROGRESS
func (s *Server) GenerateUUID(ctx context.Context, req *UUIDRequest) (*uuidgen.QuantumUUIDMetadata, error) {
	uuid, err := uuidgen.GenerateQuantumUUID()
	if err != nil {
		log.Error().Err(err).Msg("QUUID generation failed")
		return nil, fmt.Errorf("Error generating QUUID: %v", err)
	}
	err = s.dbStore.Save(uuid)
	if err != nil {
		log.Error().Err(err).Msg("QUUID store failed")
		return nil, fmt.Errorf("Error storing UUID: %v", err)
	}
	uuid, err = s.dbStore.GetPublicData(uuid.UUID)
	if err != nil {
		log.Error().Err(err).Msg("failed to get QUUID from DB")
		return nil, fmt.Errorf("Error fetching QUUID from DB: %v", err)
	}
	return uuid, nil
}
