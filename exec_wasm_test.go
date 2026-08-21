//go:build js || wasip1

package bottle

import (
	"net/http"
	"strings"
	"testing"
)

// TestExecWasmRefusesWithAReason: this file exists only for wasm builds, so the
// native lane never runs it — and an error path no lane executes is a message
// nobody has read. A wasm host cannot replace its process image; saying so by
// name beats a nil-func panic.
func TestExecWasmRefusesWithAReason(t *testing.T) {
	err := Exec("/usr/bin/tool", []string{"tool", "--help"}, nil)
	if err == nil {
		t.Fatal("a wasm host has no execve; Exec must fail")
	}
	if !strings.Contains(err.Error(), "/usr/bin/tool") {
		t.Errorf("the message does not name what it refused to exec: %v", err)
	}
	if !strings.Contains(err.Error(), "wasm host") {
		t.Errorf("the message does not say why: %v", err)
	}
}

// TestNewHTTPClientHasNoDialer is the fix, asserted where it matters. Under
// GOOS=js, net/http reaches the network through fetch only when the transport
// has no custom dialer — set one and every request falls back to Go's
// in-process fake network and a live registry answers "connection refused".
// Measured in headless Chrome, one field at a time.
func TestNewHTTPClientHasNoDialer(t *testing.T) {
	c := NewHTTPClient()
	st, ok := c.Transport.(*stallTransport)
	if !ok {
		t.Fatalf("transport = %T, want the stall watchdog", c.Transport)
	}
	tr, ok := st.base.(*http.Transport)
	if !ok {
		t.Fatalf("base = %T", st.base)
	}
	if tr.DialContext != nil || tr.Dial != nil {
		t.Error("a custom dialer disables fetch: every browser request would fail")
	}
	if tr.TLSClientConfig != nil {
		t.Error("the browser owns TLS; a client config here is dead weight")
	}
}
