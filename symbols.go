package bottle

// Shared string symbols for the pkgx bottle ecosystem — named once here so
// bottle, bk and pkgm reference constants instead of scattering magic literals.
// (The OCI media types live near their use in oci.go as MediaBottleLayer*, and
// the manifest annotation keys in verify.go as *Annotation; those are already
// named constants — this file gathers the remaining recurring literals.)
const (
	// ExtTarGz / ExtTarXz are the two bottle tarball extensions; ext also selects
	// the OCI layer media type on push.
	ExtTarGz = ".tar.gz"
	ExtTarXz = ".tar.xz"

	// GlibcProject is the pkgx project that provides the C library + loader; it
	// is the implicit from-scratch root on linux and the bottle whose manifest
	// carries the glibc min-kernel annotation.
	GlibcProject = "gnu.org/glibc"
)
