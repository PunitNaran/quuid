package main

import (
	"encoding/json"
	"flag"
	"os"

	"pq-uuid.internal/internal/uuidgen"
	"pq-uuid.internal/pkg/config"
	"pq-uuid.internal/pkg/logger"
	"pq-uuid.internal/server"

	"net"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
)

func main() {
	// Parse flags to determine the mode
	mode := flag.String("mode", "server", "Run mode: server, standalone, rpc")
	tlsCertFile := flag.String("tls-cert", "server.crt", "Path to TLS certificate file")
	tlsKeyFile := flag.String("tls-key", "server.key", "Path to TLS private key file")
	mtls := flag.Bool("mtls", false, "Enable mutual TLS")
	http3 := flag.Bool("http3", false, "Enable HTTP/3 support")

	flag.Parse()

	// Initialize logger
	logger.Init()

	// Parse the configuration (e.g., TLS, mTLS)
	cfg := config.ParseFlags(*tlsCertFile, *tlsKeyFile, *mtls, *http3)

	// Depending on mode, execute the relevant logic
	switch *mode {
	case "server":
		server.RunServer(cfg, server.NewServer())
	case "standalone":
		runStandalone()
	case "rpc":
		runRPC()
	default:
		log.Printf("Invalid mode: %s. Valid options are: server, standalone, rpc", *mode)
		log.Fatal()
	}
}

func runStandalone() {
	// Generate and print QUUID in CLI mode
	uuid, err := uuidgen.GenerateQuantumUUID()
	if err != nil {
		log.Fatal().Msgf("Error generating UUID: %v", err)
	}
	data, err := json.Marshal(uuid)
	if err != nil {
		log.Fatal().Msgf("Error marshalling UUID: %v", err)
	}
	err = os.WriteFile("./qquid.json", data, 0644)
	if err != nil {
		log.Fatal().Msgf("Error unable to write to file: %v", err)
	}
}

func runRPC() {
	// Start the gRPC server
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatal().Msgf("failed to listen: %v", err)
	}

	// Create a new gRPC server
	s := grpc.NewServer()

	// TODO: Register the QUUID generation service
	// rpc.RegisterUUIDGenerationServer(s, &rpc.Server{})

	// Start the gRPC server
	log.Printf("gRPC server listening on :50051")
	if err := s.Serve(lis); err != nil {
		log.Fatal().Msgf("failed to serve: %v", err)
	}
}
