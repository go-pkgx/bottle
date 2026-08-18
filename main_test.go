package bottle

import (
	"os"
	"testing"
)

// TestMain removes the publish settle window for the whole suite. It exists to
// make a concurrent-writer clobber detectable in production (see
// mergePlatformIntoIndex), and two seconds per push would otherwise be paid by
// every test that publishes — several minutes of sleeping for nothing. Tests
// that care about the window install their own.
func TestMain(m *testing.M) {
	indexSettle = func() {}
	os.Exit(m.Run())
}
