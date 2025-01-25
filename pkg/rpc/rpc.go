package rpc

import (
	"context"
	"fmt"

	"pq-uuid.internal/internal/uuidgen"
)

// Server implements the UUIDGeneration gRPC service
type Server struct{}

// UUIDRequest and UUIDResponse are the request and response types for gRPC
type UUIDRequest struct{}
type UUIDResponse struct {
	Uuid string
}

// GenerateUUID generates and returns a quantum-resistant UUID
func (s *Server) GenerateUUID(ctx context.Context, req *UUIDRequest) (*UUIDResponse, error) {
	quuid, err := uuidgen.GenerateQuantumUUID()
	if err != nil {
		return nil, fmt.Errorf("error generating UUID: %v", err)
	}
	return &UUIDResponse{Uuid: quuid.UUID}, nil
}
