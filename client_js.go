//go:build js

package bottle

import "net/http"

// NewHTTPClient builds the *http.Client used in a browser.
//
// It must NOT set DialContext, and that is the whole reason this file exists.
// Under GOOS=js there is no TCP: net/http reaches the network through the
// WHATWG Fetch API, and (*http.Transport).RoundTrip only takes that path when
// the transport has no custom dialer. Set one and every request falls back to
// Go's in-process fake network, so a page gets
//
//	Get "http://…/v2/": dial tcp …: connect: Connection refused
//
// for a registry that is up and answering. Measured in headless Chrome, one
// field at a time: an empty transport and one with TLSClientConfig both return
// 200; the same transport plus DialContext is the only one that fails.
//
// The rest of the native client's machinery has no meaning here either. The
// browser owns TLS and the trust store, so CertPool's embedded bundle is moot;
// and fetch exposes no dial or TLS-handshake phase to put a deadline on.
//
// The stall watchdog stays: it watches the response BODY for silence, which is
// transport-independent — and a bottle is exactly the kind of long download it
// exists for.
func NewHTTPClient() *http.Client {
	return &http.Client{
		Transport: &stallTransport{
			idle: stallTimeout,
			base: &http.Transport{},
		},
	}
}
