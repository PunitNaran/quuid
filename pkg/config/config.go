package config

// Config struct to hold TLS and other configurations
type Config struct {
	Domain      string
	TLSCertFile string
	TLSKeyFile  string
	MTLS        bool
	HTTP3       bool
}

// ParseFlags parses the command-line flags and returns a Config
func ParseFlags(domain, certFile, keyFile string, mtls, http3 bool) *Config {
	return &Config{
		Domain:      domain,
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
		MTLS:        mtls,
		HTTP3:       http3,
	}
}
