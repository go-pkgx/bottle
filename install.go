package bottle

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Exec runs (or, on UNIX, replaces the current process image with) the target
// binary; overridable in tests. Its concrete value is platform-specific:
//   - UNIX (exec_unix.go): syscall.Exec — replaces the process, never returns
//     on success.
//   - Windows (exec_windows.go): spawns the child with inherited stdio, waits,
//     and exits the parent with the child's exit code (Windows has no execve).
//
// The signature is identical on every platform, so callers are unchanged.
var Exec func(argv0 string, argv []string, env []string) error

// ResolveBinPath maps a logical bin path (…/bin/foo) to the file that actually
// exists on disk. On Windows it prefers "foo.exe" (the PE image the toolchain
// produces), falling back to the bare name; on UNIX it is the identity. This
// keeps BinNames/PrimaryBin returning logical, extension-free names while the
// run/stub sites resolve to the real executable.
func ResolveBinPath(bin string) string {
	if goos() == "windows" && !strings.HasSuffix(bin, ".exe") {
		if _, err := os.Stat(bin + ".exe"); err == nil {
			return bin + ".exe"
		}
	}
	return bin
}

// BinNames returns the base names of the binaries a package provides, falling
// back to the project's leaf name when it declares no `provides:`.
func BinNames(project string, provides []string) []string {
	var names []string
	for _, prov := range provides {
		if prov = strings.TrimSpace(prov); strings.HasPrefix(prov, "bin/") {
			names = append(names, filepath.Base(prov))
		}
	}
	if len(names) == 0 {
		names = append(names, filepath.Base(project))
	}
	return names
}

// PrimaryBin picks the binary to run for a project: the one whose name matches
// the project's path leaf (gnu.org/wget -> wget) or its domain's second-level
// label (perl.org -> perl, not the first-listed corelist), else the first
// provided binary.
func PrimaryBin(project string, provides []string) string {
	names := BinNames(project, provides)
	cands := []string{filepath.Base(project)}
	if !strings.Contains(project, "/") {
		if i := strings.Index(project, "."); i > 0 {
			cands = append(cands, project[:i])
		}
	}
	for _, c := range cands {
		for _, n := range names {
			if n == c {
				return n
			}
		}
	}
	return names[0]
}

// IsELF reports whether the file at p starts with the ELF magic.
func IsELF(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	if _, err := f.Read(magic[:]); err != nil {
		return false
	}
	return magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F'
}

// PrefixOf returns the installed prefix directory <dir>/<project>/v<version>
// for the Resolved whose Project equals project in the closure, or "" if the
// project is not part of the closure.
func PrefixOf(project string, closure []Resolved, dir string) string {
	for _, r := range closure {
		if r.Project == project {
			return filepath.Join(dir, project, "v"+r.Version.Raw)
		}
	}
	return ""
}

// StubBins writes a small env-setting shell stub into <prefix>/bin for every
// binary in the closure, mirroring the reference pkgm: the stub exports the
// closure's LD_LIBRARY_PATH and exec's the real bottle binary.
func StubBins(closure []Resolved, dir, prefix string) (int, error) {
	binDir := filepath.Join(prefix, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return 0, err
	}
	libPath := LibPath(closure, dir)
	n := 0
	for _, r := range closure {
		pkgPrefix := filepath.Join(dir, r.Project, "v"+r.Version.Raw)
		_, provides, err := FetchMeta(r.Project)
		if err != nil {
			continue
		}
		for _, name := range BinNames(r.Project, provides) {
			real := filepath.Join(pkgPrefix, "bin", name)
			if _, err := os.Stat(real); err != nil {
				continue
			}
			stub := fmt.Sprintf("#!/bin/sh\nexport LD_LIBRARY_PATH=\"%s${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\"\nexec \"%s\" \"$@\"\n", libPath, real)
			dst := filepath.Join(binDir, name)
			_ = os.Remove(dst)
			if err := os.WriteFile(dst, []byte(stub), 0o755); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

// LibDirs returns every library directory in an installed closure (including
// glibc's versioned sub-libdir on linux). It is the list form of LibPath, used
// where an OS-native path separator is required (Windows joins with ";" and
// resolves DLLs from these dirs via PATH, so a ":"-joined string is wrong).
func LibDirs(closure []Resolved, dir string) []string {
	var paths []string
	for _, r := range closure {
		prefix := filepath.Join(dir, r.Project, "v"+r.Version.Raw)
		for _, sub := range []string{"lib", "lib64"} {
			p := filepath.Join(prefix, sub)
			if st, err := os.Stat(p); err == nil && st.IsDir() {
				paths = append(paths, p)
			}
			matches, _ := filepath.Glob(filepath.Join(prefix, sub, "glibc-*"))
			paths = append(paths, matches...)
		}
	}
	return paths
}

// LibPath returns a ":"-joined library path covering every lib dir in an
// installed closure (including glibc's versioned sub-libdir). It is the value
// of $LD_LIBRARY_PATH used on linux; on Windows use LibDirs with the native
// separator instead.
func LibPath(closure []Resolved, dir string) string {
	return strings.Join(LibDirs(closure, dir), ":")
}

// LoaderName is the dynamic-loader soname for the current architecture.
func LoaderName() string {
	return map[string]string{
		"aarch64": "ld-linux-aarch64.so.1",
		"x86-64":  "ld-linux-x86-64.so.2",
	}[goarch()]
}

// FindLoader locates the pkgx glibc dynamic loader in an installed closure.
func FindLoader(dir string) string {
	name := LoaderName()
	if name == "" {
		return ""
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "gnu.org/glibc", "v*", "lib", "glibc-*", name))
	if len(matches) > 0 {
		return matches[len(matches)-1]
	}
	return ""
}

var loaderDirs = []string{"/lib", "/lib64"}

// SetupScratchRootfs makes the pkgx loader and a shell available at their
// canonical absolute paths (best-effort). On a FROM-scratch image this lets
// every bottle ELF — the one we exec AND any child processes it spawns —
// resolve its PT_INTERP=/lib/ld-linux natively, and (when shellPath is set)
// lets "#!/bin/sh" wrapper scripts resolve to the pkgx bash we installed. On a
// normal system these paths already exist, so os.Symlink fails and is ignored
// (no clobbering).
func SetupScratchRootfs(loader, shellPath string) {
	if name := LoaderName(); name != "" {
		for _, d := range loaderDirs {
			_ = os.MkdirAll(d, 0o755)
			_ = os.Symlink(loader, filepath.Join(d, name))
		}
	}
	if shellPath != "" {
		_ = os.MkdirAll("/bin", 0o755)
		_ = os.Symlink(shellPath, "/bin/sh")
	}
}

// MergeClosures appends the packages of b not already in a (dedup by project).
func MergeClosures(a, b []Resolved) []Resolved {
	have := map[string]bool{}
	for _, r := range a {
		have[r.Project] = true
	}
	for _, r := range b {
		if !have[r.Project] {
			a = append(a, r)
			have[r.Project] = true
		}
	}
	return a
}

// FindClosureBin returns the path to <project>/…/bin/<name> if that project is
// in the installed closure, else "".
func FindClosureBin(closure []Resolved, dir, project, name string) string {
	for _, r := range closure {
		if r.Project == project {
			p := filepath.Join(dir, project, "v"+r.Version.Raw, "bin", name)
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}

// CanonicalLoaderExists reports whether /lib{,64}/ld-linux-* is present.
func CanonicalLoaderExists() bool {
	name := LoaderName()
	if name == "" {
		return false
	}
	for _, d := range loaderDirs {
		if _, err := os.Lstat(filepath.Join(d, name)); err == nil {
			return true
		}
	}
	return false
}
