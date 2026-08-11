package bottle

import (
	"os"
	"path/filepath"
	"testing"
)

// setConfigPath points the loader at path and resets the one-shot cache,
// restoring the seams (and cache) when the test finishes.
func setConfigPath(t *testing.T, path string) {
	t.Helper()
	oldPath, oldLookup := configPathFn, lookupEnv
	configPathFn = func() (string, error) { return path, nil }
	reloadConfig()
	t.Cleanup(func() {
		configPathFn, lookupEnv = oldPath, oldLookup
		reloadConfig()
	})
}

// writeConfig writes content to a temp config file and points the loader at it.
func writeConfig(t *testing.T, content string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.hcl2")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	setConfigPath(t, path)
}

// setLookup installs a lookupEnv seam backed by m (present iff the key exists).
func setLookup(m map[string]string) {
	lookupEnv = func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestConfigValueTypes(t *testing.T) {
	writeConfig(t, `
# comment
// line comment
/* block
   comment */
PKGX_DIST   = "oci://ghcr.io/go-pkgx/packages"
ESC         = "a\"b\\c\nd\te"
PKGX_VERIFY = true
DISABLED    = false
PORT        = 5000
RATIO       = 1.5
EMPTY       = ""
`)
	setLookup(nil)
	cases := map[string]string{
		"PKGX_DIST":   "oci://ghcr.io/go-pkgx/packages",
		"ESC":         "a\"b\\c\nd\te",
		"PKGX_VERIFY": "true",
		"DISABLED":    "false",
		"PORT":        "5000",
		"RATIO":       "1.5",
		"EMPTY":       "",
	}
	for k, want := range cases {
		if got := Env(k); got != want {
			t.Errorf("Env(%q) = %q, want %q", k, got, want)
		}
	}
	if err := ConfigError(); err != nil {
		t.Errorf("ConfigError() = %v, want nil", err)
	}
	// An attribute absent from the file resolves to "".
	if got := Env("NOT_PRESENT"); got != "" {
		t.Errorf("Env(absent) = %q, want empty", got)
	}
}

func TestEnvPrecedence(t *testing.T) {
	writeConfig(t, `PKGX_DIST = "fromfile"`)

	// A real env var, set and non-empty, wins over the file.
	setLookup(map[string]string{"PKGX_DIST": "fromenv"})
	if got := Env("PKGX_DIST"); got != "fromenv" {
		t.Errorf("env should win: got %q", got)
	}
	// A present-but-empty env var falls back to the file.
	setLookup(map[string]string{"PKGX_DIST": ""})
	if got := Env("PKGX_DIST"); got != "fromfile" {
		t.Errorf("empty env should fall back to file: got %q", got)
	}
	// An absent env var falls back to the file.
	setLookup(nil)
	if got := Env("PKGX_DIST"); got != "fromfile" {
		t.Errorf("absent env should fall back to file: got %q", got)
	}
	// Absent everywhere → "".
	if got := Env("PKGX_PANTRY"); got != "" {
		t.Errorf("absent everywhere = %q, want empty", got)
	}
}

func TestConfigMissingFile(t *testing.T) {
	setConfigPath(t, filepath.Join(t.TempDir(), "does-not-exist.hcl2"))
	setLookup(nil)
	if got := Env("PKGX_DIST"); got != "" {
		t.Errorf("missing file Env = %q, want empty", got)
	}
	if err := ConfigError(); err != nil {
		t.Errorf("missing file must not be an error, got %v", err)
	}
}

func TestConfigParseError(t *testing.T) {
	writeConfig(t, `@@@ not valid hcl @@@`)
	setLookup(map[string]string{"PKGX_DIST": "fromenv"})
	if err := ConfigError(); err == nil {
		t.Fatal("expected a parse error")
	}
	// A live env var still resolves despite the broken file.
	if got := Env("PKGX_DIST"); got != "fromenv" {
		t.Errorf("env should still resolve on parse error: got %q", got)
	}
	// A file-only key falls back to "" (map stayed empty).
	if got := Env("PKGX_PANTRY"); got != "" {
		t.Errorf("parse-error fallback = %q, want empty", got)
	}
}

func TestConfigBlockRejected(t *testing.T) {
	// JustAttributes rejects blocks: an attributes-only settings file.
	writeConfig(t, `service { name = "x" }`)
	setLookup(nil)
	if err := ConfigError(); err == nil {
		t.Fatal("expected an error for a block")
	}
}

func TestConfigBadExpression(t *testing.T) {
	// A bare identifier is a variable reference; with a nil EvalContext it errors.
	writeConfig(t, `PKGX_DIST = somevar`)
	setLookup(nil)
	if err := ConfigError(); err == nil {
		t.Fatal("expected an error for an unresolvable expression")
	}
}

func TestConfigUnsupportedType(t *testing.T) {
	// A tuple is a valid HCL expression but not a scalar the tools accept.
	writeConfig(t, `PKGX_DIST = ["a", "b"]`)
	setLookup(nil)
	if err := ConfigError(); err == nil {
		t.Fatal("expected an error for a non-scalar value")
	}
}

func TestConfigPathError(t *testing.T) {
	oldPath, oldLookup := configPathFn, lookupEnv
	defer func() {
		configPathFn, lookupEnv = oldPath, oldLookup
		reloadConfig()
	}()
	configPathFn = func() (string, error) { return "", os.ErrPermission }
	setLookup(nil)
	reloadConfig()
	if err := ConfigError(); err == nil {
		t.Fatal("expected the configPathFn error to surface")
	}
	if got := Env("PKGX_DIST"); got != "" {
		t.Errorf("path error Env = %q, want empty", got)
	}
}

func TestConfigStatError(t *testing.T) {
	// A regular file used as a directory component yields ENOTDIR (not IsNotExist).
	f := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	setConfigPath(t, filepath.Join(f, "config.hcl2"))
	setLookup(nil)
	if err := ConfigError(); err == nil {
		t.Fatal("expected a non-IsNotExist stat error to surface")
	}
}

func TestParseConfigFileReadError(t *testing.T) {
	// parseConfigFile reads the file itself; a path that exists but cannot be
	// read as a regular file (a directory) must surface the read error. This
	// covers the branch between loadConfig's successful Stat and the parse.
	dir := t.TempDir()
	if _, err := parseConfigFile(dir); err == nil {
		t.Fatal("expected a read error for a directory path")
	}
}

func TestConfigDefaultPath(t *testing.T) {
	// Exercise the real configPathFn (UserHomeDir-based) with a home that has no
	// config file: it must resolve cleanly to "" with no error.
	oldLookup := lookupEnv
	defer func() { lookupEnv = oldLookup; reloadConfig() }()
	setLookup(nil)
	t.Setenv("HOME", t.TempDir())
	reloadConfig()
	if got := Env("PKGX_DIST"); got != "" {
		t.Errorf("default-path Env = %q, want empty", got)
	}
	if err := ConfigError(); err != nil {
		t.Errorf("default-path ConfigError = %v, want nil", err)
	}
}
