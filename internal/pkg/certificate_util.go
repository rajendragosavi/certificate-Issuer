package pkg

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// TLSCertificate stores the PEM encoded certificate and private key
type TLSCertificate struct {
	Certificate []byte
	PrivateKey  []byte
	ExpiringON  time.Time
}

// Parse the validity string (e.g., "360d", "24h", "60m")
func ParseDuration(input string) (time.Duration, error) {
	if strings.HasSuffix(input, "d") {
		daysStr := strings.TrimSuffix(input, "d")
		days, err := strconv.Atoi(daysStr)
		if err != nil {
			return 0, fmt.Errorf("invalid duration: %s", input)
		}
		return time.Hour * 24 * time.Duration(days), nil
	}

	// Fallback to Go's built-in time.ParseDuration for hours, minutes, and seconds
	return time.ParseDuration(input)
}

// Helper function to encode ECDSA private key to PEM format
func PemBlockForKey(priv *ecdsa.PrivateKey) *pem.Block {
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		panic(err) // Handle this error properly in production
	}
	return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
}
