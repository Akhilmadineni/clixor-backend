package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// Client returns a TLS configuration using the system trust store plus the
// optional private deployment CA. ServerName is still derived by each client
// from the connection URL, so hostname verification remains enabled.
func Client(caFile string) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if caFile != "" {
		pemBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read TLS CA file: %w", err)
		}
		if !roots.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("TLS CA file contains no certificates")
		}
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
	}, nil
}
