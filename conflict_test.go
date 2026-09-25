package bottle

import (
	"errors"
	"strings"
	"testing"
)

// A refusal a caller can COUNT, not only print. Asking how much of a pantry a
// chosen base reaches means resolving hundreds of closures and aggregating
// which demand did the excluding; parsing the sentence would be the wrong way
// to learn it.
func TestConflictErrorIsStructured(t *testing.T) {
	osn, arch := HostSlug()
	versions := map[string][]string{
		"app.org/x/" + osn + "/" + arch: {"1.0.0"},
		"lib.org/z/" + osn + "/" + arch: {"2.1.0", "3.0.0"},
	}
	defer crossPantry(t, map[string]string{
		"app.org/x": "dependencies:\n  lib.org/z: ^2\nprovides:\n  - bin/x\n",
		"lib.org/z": "provides:\n  - lib/libz.so\n",
	}, versions)()

	// The root demands ^3, app.org/x demands ^2, and nothing satisfies both.
	_, err := GraphFor(map[string]string{"app.org/x": "*", "lib.org/z": "^3"}, osn, arch)
	if err == nil {
		t.Fatal("an unsatisfiable closure resolved")
	}
	var ce *ConflictError
	if !errors.As(err, &ce) {
		t.Fatalf("error is not a *ConflictError: %T %v", err, err)
	}
	if ce.Project != "lib.org/z" {
		t.Errorf("Project = %q, want lib.org/z", ce.Project)
	}
	if len(ce.Constraints) != len(ce.AskedBy) || len(ce.Constraints) != 2 {
		t.Fatalf("Constraints=%v AskedBy=%v, want two of each", ce.Constraints, ce.AskedBy)
	}
	// Whoever made each demand is named, and a root is "requested".
	pairs := map[string]string{}
	for i := range ce.Constraints {
		pairs[ce.Constraints[i]] = ce.AskedBy[i]
	}
	if pairs["^3"] != "requested" || pairs["^2"] != "app.org/x" {
		t.Errorf("pairs = %v", pairs)
	}
	// And it still reads the way it always did.
	if !strings.Contains(err.Error(), "asked for by") || !strings.Contains(err.Error(), "^2 (app.org/x)") {
		t.Errorf("message lost its shape: %v", err)
	}
	// The version-pick failure underneath is still reachable.
	if ce.Unwrap() == nil {
		t.Error("Unwrap returned nothing")
	}
}

// One demand is not a conflict: the error passes through unwrapped, because
// there is nothing to attribute.
func TestASingleDemandIsNotAConflict(t *testing.T) {
	osn, arch := HostSlug()
	defer crossPantry(t, map[string]string{
		"app.org/y": "provides:\n  - bin/y\n",
	}, map[string][]string{"app.org/y/" + osn + "/" + arch: {"1.0.0"}})()

	_, err := GraphFor(map[string]string{"app.org/y": "^9"}, osn, arch)
	if err == nil {
		t.Fatal("an unsatisfiable root resolved")
	}
	var ce *ConflictError
	if errors.As(err, &ce) {
		t.Errorf("a single demand was reported as a conflict: %+v", ce)
	}
}
