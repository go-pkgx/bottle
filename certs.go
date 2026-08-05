package bottle

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"net/http"
	"time"
)

// cacert is the Mozilla CA bundle, compiled into the binary so TLS works on a
// bare `FROM scratch` image with no system trust store.
//
//go:embed cacert.pem
var cacert []byte

// HTTPClient is an HTTP client that trusts the embedded CA bundle (falling
// back to the system pool if, somehow, the embed is empty). It is overridable.
var HTTPClient = NewHTTPClient()

// systemCertPool is x509.SystemCertPool, swappable in tests so the
// no-system-trust-store fallback (an unusual platform, or a scratch image) is
// exercisable on a host that does have one.
var systemCertPool = x509.SystemCertPool

// NewHTTPClient builds an *http.Client that trusts the embedded CA bundle in
// addition to the host's system trust store.
func NewHTTPClient() *http.Client {
	pool, err := systemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	pool.AppendCertsFromPEM(cacert)
	return &http.Client{
		Timeout: 5 * time.Minute,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}
}
