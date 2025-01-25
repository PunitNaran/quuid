package api

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// RegisterHealthCheck adds the health check endpoint to the Echo router
func RegisterHealthCheck(e *echo.Echo) {
	e.GET("/health", func(c echo.Context) error {
		return c.String(http.StatusOK, "Service is running")
	})
}
