package logger

import (
	"os"

	"github.com/rs/zerolog"
)

// Init initializes the global logger instance
func Init() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log := zerolog.New(os.Stderr).With().Timestamp().Logger()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)

	// Optional: For more complex logging (JSON, different output formats)
	log.Info().Msg("Logger Initialized")
}
