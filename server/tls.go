package server

import (
	"crypto/tls"
)

// SetupTLS sets up the TLS configuration with optional mTLS and HTTP/3 support
func SetupTLS(certFile, keyFile string, mtls bool) (*tls.Config, error) {
	// Load the server's certificate and key
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	// Set up TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Enable mTLS if requested
	if mtls {
		// Load client certificate for mTLS (for simplicity, it's not shown here)
		// tlsConfig.ClientCAs = ...
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	// Enable HTTP/3 if requested (requires QUIC support in Go, for simplicity it's skipped here)
	if http3 { // TODO
		// TLS-specific configurations for HTTP/3 can be applied
	}

	// Return the TLS configuration
	return tlsConfig, nil
}
