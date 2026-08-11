package bottle

// config.go loads user defaults for the go-pkgx tools from ~/.pkgx/config.hcl2.
//
// The file is an HCL2 top-level-attribute settings file: a flat list of
// `NAME = <value>` attributes (no blocks), where <value> is a string, bool, or
// number. Any PKGX_* / OCI_* variable the tools read can be given a default
// here. It is parsed with the org's own pure-Go, zero-dependency HCL2 library
// (github.com/go-ruby-hcl2/hcl2), so every attribute is handled uniformly and
// the standard HCL2 comment/quoting/escape rules apply — with no third-party
// dependency to vendor.
//
// Precedence (see Env): a real process environment variable — present AND
// non-empty — always wins; otherwise the value from config.hcl2 is used;
// otherwise the empty string. This lets the file set defaults that a live
// environment variable can still override.

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/go-ruby-hcl2/hcl2"
)

// lookupEnv is os.LookupEnv, swappable in tests.
var lookupEnv = os.LookupEnv

// configPathFn resolves the config file path. It is a var so tests can point it
// at a temporary file (or make it fail). It is deliberately based on the user
// home directory — always ~/.pkgx/config.hcl2 — and NOT on PKGX_DIR, both to
// avoid a circular dependency (PKGX_DIR is itself resolved through Env) and
// because the location is a fixed, well-known settings path.
var configPathFn = func() (string, error) {
	home, err := os.UserHomeDir()
	return filepath.Join(home, ".pkgx", "config.hcl2"), err
}

var (
	configOnce sync.Once
	configMap  map[string]string
	configErr  error
)

// loadConfig reads and parses ~/.pkgx/config.hcl2 exactly once. It is tolerant:
// a missing file yields an empty map and no error; a path or parse failure
// yields an empty map and a stored error (see ConfigError). Reads therefore
// always fall back cleanly to environment variables / built-in defaults.
func loadConfig() {
	configOnce.Do(func() {
		configMap = map[string]string{}
		path, err := configPathFn()
		if err != nil {
			configErr = err
			return
		}
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				return // absent file → empty map, no error
			}
			configErr = err
			return
		}
		m, err := parseConfigFile(path)
		if err != nil {
			configErr = err
			return // keep the empty map so reads fall back
		}
		configMap = m
	})
}

// parseConfigFile parses an HCL2 top-level-attribute file into a string map.
// Blocks are rejected (the file is attributes-only, matching the semantics of
// hashicorp/hcl's JustAttributes). Each attribute expression is evaluated with a
// nil context — so a bare identifier is an unresolved-variable error, exactly as
// before — and the resulting scalar is rendered by valueToString.
func parseConfigFile(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	body, err := hcl2.Parse(string(b))
	if err != nil {
		return nil, err
	}
	if len(body.Blocks) > 0 {
		return nil, fmt.Errorf("config %s: blocks are not allowed, only top-level attributes", path)
	}
	out := make(map[string]string, len(body.Attributes))
	for _, a := range body.Attributes {
		v, _, err := body.Attr(a.Name, nil)
		if err != nil {
			return nil, err
		}
		s, err := valueToString(v)
		if err != nil {
			return nil, err
		}
		out[a.Name] = s
	}
	return out, nil
}

// valueToString renders a scalar HCL2 value as the string form the tools consume:
// a string as-is, a bool as "true"/"false", and a number without trailing zeros
// (so `PKGX_VERIFY = true` → "true" and a port stays clean). hcl2 narrows an
// integral number to int64 and a fractional one to float64. Any other type
// (tuple, object, null, …) is rejected — the settings file is scalar-only.
func valueToString(v hcl2.Value) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	case bool:
		if x {
			return "true", nil
		}
		return "false", nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), nil
	default:
		return "", fmt.Errorf("unsupported config value: attributes must be a string, bool, or number, got %T", v)
	}
}

// Env resolves a variable for the go-pkgx tools. A real process environment
// variable that is set AND non-empty wins; otherwise the value from
// ~/.pkgx/config.hcl2 is returned; otherwise the empty string.
func Env(name string) string {
	if v, ok := lookupEnv(name); ok && v != "" {
		return v
	}
	loadConfig()
	return configMap[name]
}

// ConfigError returns the error, if any, from loading ~/.pkgx/config.hcl2. It is
// nil when the file parsed cleanly or is simply absent, and non-nil only on a
// real path or parse failure (in which case reads fall back to the environment).
func ConfigError() error {
	loadConfig()
	return configErr
}

// reloadConfig resets the one-shot loader so tests can re-read the file after
// swapping the configPathFn / lookupEnv seams.
func reloadConfig() {
	configOnce = sync.Once{}
	configMap = nil
	configErr = nil
}
