package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"pq-uuid.internal/internal/uuidgen"
	"pq-uuid.internal/pkg/api"
	"pq-uuid.internal/pkg/config"
	"pq-uuid.internal/pkg/logger"
	"pq-uuid.internal/pkg/rpc"
	"pq-uuid.internal/server"

	"net"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
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
		runServer(cfg)
	case "standalone":
		runStandalone()
	case "rpc":
		runRPC()
	default:
		log.Fatalf("Invalid mode: %s. Valid options are: server, standalone, rpc", *mode)
	}
}

func runServer(cfg *config.Config) {
	// Initialize Echo instance
	e := echo.New()

	// Setup middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.RequestID())

	// Health check endpoint
	api.RegisterHealthCheck(e)

	// API route for UUID generation
	e.GET("/uuid", func(c echo.Context) error {
		uuid, err := uuidgen.GenerateQuantumUUID()
		if err != nil {
			return c.String(http.StatusInternalServerError, fmt.Sprintf("Error generating UUID: %v", err))
		}
		return c.String(http.StatusOK, uuid.UUID)
	})

	// Setup TLS and hitless rotation
	tlsConfig, err := server.SetupTLS(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.MTLS)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to setup TLS")
	}

	// Create HTTP server with TLS configuration
	s := &http.Server{
		Addr:      ":443",
		TLSConfig: tlsConfig,
	}

	// Graceful Shutdown Handling
	go func() {
		if err := s.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("Server failed")
		}
	}()

	// Handle graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	// Block until a termination signal is received
	<-stop

	// Gracefully shutdown the server with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.Shutdown(ctx); err != nil {
		log.Fatal().Err(err).Msg("Server shutdown failed")
	}

	log.Info().Msg("Server gracefully stopped")
}

func runStandalone() {
	// Generate and print UUID in CLI mode
	uuid, err := uuidgen.GenerateQuantumUUID()
	if err != nil {
		log.Fatalf("Error generating UUID: %v", err)
	}
	fmt.Println("Generated Quantum UUID:", uuid)
}

func runRPC() {
	// Start the gRPC server
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	// Create a new gRPC server
	s := grpc.NewServer()

	// Register the UUID generation service
	rpc.RegisterUUIDGenerationServer(s, &rpc.Server{})

	// Start the gRPC server
	log.Printf("gRPC server listening on :50051")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
