package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"pq-uuid.internal/internal/db"
	"pq-uuid.internal/internal/uuidgen"
	"pq-uuid.internal/pkg/api"
	"pq-uuid.internal/pkg/config"

	quic "github.com/quic-go/quic-go"
	http3_server "github.com/quic-go/quic-go/http3"
)

var dbStore db.DBInterface

func init() {
	dbStore = db.NewInMemoryDB()
}

type validateRequest struct {
	QuantumUUID string                      `json:"quantumUUID"`
	Metadata    uuidgen.QuantumUUIDMetadata `json:"metadata"`
}

// NewServer creates a new Echo server with secure TLS configurations and HTTP/3 support
func NewServer() *echo.Echo {
	// UNIX Time is faster and smaller than most timestamps
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	// Initialize Echo instance
	e := echo.New()

	// Setup middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.RequestID())

	// Route for UUID generation
	// API route for QUUID generation
	e.GET("/quuid", func(c echo.Context) error {
		uuid, err := uuidgen.GenerateQuantumUUID()
		if err != nil {
			log.Error().Err(err).Msg("QUUID generation failed")
			return c.String(http.StatusInternalServerError, fmt.Sprintf("Error generating QUUID: %v", err))
		}
		err = dbStore.Save(uuid)
		if err != nil {
			log.Error().Err(err).Msg("QUUID store failed")
			return c.String(http.StatusInternalServerError, fmt.Sprintf("Error storing UUID: %v", err))
		}
		uuid, err = dbStore.GetPublicData(uuid.UUID)
		if err != nil {
			log.Error().Err(err).Msg("failed to get QUUID from DB")
			return c.String(http.StatusInternalServerError, fmt.Sprintf("Error fetching QUUID from DB: %v", err))
		}
		return c.JSON(http.StatusOK, uuid)
	})
	e.POST("/validate", func(c echo.Context) error {
		var request validateRequest
		if err := c.Bind(&request); err != nil {
			log.Error().Err(err).Msg("Invalid request body")
			return c.String(http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
		}
		isValid, err := uuidgen.ValidateQuantumUUID(request.QuantumUUID, request.Metadata)
		if err != nil {
			log.Error().Err(err).Msg("UUID validation failed")
			return c.String(http.StatusInternalServerError, fmt.Sprintf("Error validating UUID: %v", err))
		}

		// Return response based on validation result
		if isValid {
			return c.String(http.StatusOK, "Quantum UUID is valid")
		} else {
			return c.String(http.StatusBadRequest, "Invalid Quantum UUID")
		}
	})
	// Health check endpoint
	api.RegisterHealthCheck(e)

	return e
}

func RunServer(cfg *config.Config, e *echo.Echo) {
	// Setup TLS and hitless rotation
	tlsConfig, err := SetupTLS(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.MTLS)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to setup TLS")
	}
	// QUIC Server configuration
	var quicListener *quic.EarlyListener
	if cfg.HTTP3 {
		// QUIC configuration for HTTP/3
		quicListener, err = quic.ListenAddrEarly(":443", tlsConfig, &quic.Config{})
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to start QUIC listener")
		}

		// Handle HTTP/3 requests using Echo
		go func() {
			// Start QUIC server with Echo
			http3Server := &http3_server.Server{
				Handler: e,
			}
			if err := http3Server.ServeListener(quicListener); err != nil {
				log.Err(err).Msg("HTTP/3 Server failed")
				log.Fatal()
			}
		}()
	} else {
		// Default HTTP server with TLS
		s := &http.Server{
			Addr:      ":443",
			TLSConfig: tlsConfig,
		}

		go func() {
			if err := e.StartServer(s); err != nil && err != http.ErrServerClosed {
				log.Err(err).Msg("HTTP Server failed")
				log.Fatal()
			}
		}()
	}

	// Graceful shutdown with enhanced context management
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	// Block until a termination signal is received
	<-stop

	// Gracefully shutdown the server with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // Increased timeout
	defer cancel()

	if err := e.Shutdown(ctx); err != nil {
		log.Err(err).Msg("Server shutdown failed")
		log.Fatal()
	}

	log.Info().Msg("Server gracefully stopped")
}
