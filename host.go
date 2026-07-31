// Package bottle is the reusable pkgx "bottle backend": it resolves a package's
// runtime dependency closure from the pkgx pantry, downloads the bottles from
// dist.pkgx.dev, and installs them — with no runtime dependencies of its own
// (pure Go, CGO_ENABLED=0, runnable on a `FROM scratch` image). It is imported
// by the pkgm CLI and by sibling tools so there is one source of truth.
package bottle

import "runtime"

// goos returns the pkgx OS slug for the current build.
func goos() string {
	switch runtime.GOOS {
	case "darwin":
		return "darwin"
	case "windows":
		return "windows"
	default:
		return "linux"
	}
}

// goarch returns the pkgx architecture slug for the current build.
func goarch() string {
	switch runtime.GOARCH {
	case "arm64":
		return "aarch64"
	case "amd64":
		return "x86-64"
	default:
		return runtime.GOARCH
	}
}

// GOOS returns the pkgx OS slug ("linux", "darwin", or "windows") for the
// running machine.
func GOOS() string { return goos() }

// GOARCH returns the pkgx architecture slug (e.g. "x86-64", "aarch64") for the
// running machine.
func GOARCH() string { return goarch() }
