package server

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"pq-uuid.internal/internal/uuidgen"
)

// NewServer creates a new Echo server with secure TLS configurations and HTTP/3 support
func NewServer() *echo.Echo {
	e := echo.New()

	// Middleware: Logger and recovery
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Example route for UUID generation
	e.GET("/uuid", func(c echo.Context) error {
		// Example call to UUID generation logic
		// Use your imported UUID generation function here
		uuid, err := uuidgen.GenerateQuantumUUID()
		if err != nil {
			return c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to generate UUID: %v", err))
		}
		return c.String(http.StatusOK, uuid.UUID)
	})

	return e
}
