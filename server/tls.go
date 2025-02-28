package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// Generate a self-signed TLS certificate for localhost
func generateSelfSignedCert() (tls.Certificate, error) {
	// Generate a private key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Define certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"Localhost Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Encode private key and cert in PEM format
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	// Load the certificate
	return tls.X509KeyPair(certPEM, keyPEM)
}

// SetupTLS sets up the TLS configuration with optional mTLS and HTTP/3 support
func SetupTLS(domain, certFile, keyFile string, mtls bool) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	if domain == "" {
		return nil, nil // No TLS config
	}
	if domain == "localhost" {
		cert, err := generateSelfSignedCert()
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		return tlsConfig, nil
	}
	if certFile != "" && keyFile != "" {
		// Load the server's certificate and key
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}

		// Set up TLS configuration
		tlsConfig.Certificates = []tls.Certificate{cert}

		// Enable mTLS if requested
		if mtls {
			// Load client certificate for mTLS (for simplicity, it's not shown here)
			// tlsConfig.ClientCAs = ...
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
	} else {
		m := autocert.Manager{
			Cache:      autocert.DirCache("certs"), // Store certs in "certs" directory
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domain), // Restrict to specific domain
		}
		tlsConfig.GetCertificate = m.GetCertificate
	}
	// Return the TLS configuration
	return tlsConfig, nil
}
