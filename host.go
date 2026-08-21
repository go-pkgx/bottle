// Package bottle is the reusable pkgx "bottle backend": it resolves a package's
// runtime dependency closure from the pkgx pantry, downloads the bottles from
// the configured PKGX_DIST (default: the signed oci://ghcr.io/go-pkgx/packages
// registry; PKGX_DIST=https://dist.pkgx.dev for the unsigned upstream), and
// installs them — with no runtime dependencies of its own (pure Go,
// CGO_ENABLED=0, runnable on a `FROM scratch` image). It is imported by the
// pkgm CLI and by sibling tools so there is one source of truth.
package bottle

import "runtime"

// osSlug maps a Go GOOS value to the pkgx OS slug. Everything that is not
// named here is treated as linux (pkgx bottles those three families, and an
// exotic unix is closer to linux than to nothing). It is a pure function so
// every branch is unit-testable without needing to be built for that OS.
//
// js and wasip1 are named because the linux default is WRONG for them, not
// merely approximate. This package compiles and passes for both, so it runs in
// a browser and under a WASI runtime — and there it used to report
//
//	HostSlug() = "linux" / "wasm"
//
// a platform that does not exist and never will. A consumer asking the registry
// for linux/wasm bottles gets nothing, forever, with no hint as to why. They
// stay distinct from each other too: a WASI guest and a browser are different
// hosts (different imports, different capabilities), so a module built for one
// is not a bottle for the other.
func osSlug(g string) string {
	switch g {
	case "darwin":
		return "darwin"
	case "windows":
		return "windows"
	case "js":
		return "js"
	case "wasip1":
		return "wasip1"
	default:
		return "linux"
	}
}

// archSlug maps a Go GOARCH value to the pkgx architecture slug (the pass-through
// default keeps arches pkgx spells the same as Go, e.g. riscv64). Pure, for the
// same testability reason as osSlug.
func archSlug(a string) string {
	switch a {
	case "arm64":
		return "aarch64"
	case "amd64":
		return "x86-64"
	default:
		return a
	}
}

// goos / goarch return the pkgx OS / architecture slug for the running machine.
// They are function vars (defaulting to the real runtime detection, always
// routed through osSlug/archSlug so they can never disagree with it) so a test
// can exercise the OS/arch-specific code paths — Windows binary resolution, the
// linux scratch-rootfs and DT_NEEDED closure completion — that are otherwise
// unreachable on the host running the suite.
var (
	goos   = func() string { return osSlug(runtime.GOOS) }
	goarch = func() string { return archSlug(runtime.GOARCH) }
)

// GOOS returns the pkgx OS slug ("linux", "darwin", or "windows") for the
// running machine.
func GOOS() string { return goos() }

// GOARCH returns the pkgx architecture slug (e.g. "x86-64", "aarch64") for the
// running machine.
func GOARCH() string { return goarch() }
