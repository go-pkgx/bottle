package bottle

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote/errcode"
)

// ⛔ "NOT PUBLISHED HERE" AND "I COULD NOT ASK" ARE DIFFERENT ANSWERS, and
// ghcr spells the first one as 403 at the token endpoint for a repository
// that does not exist. A user met that raw:
//
//	pkgx: … is not published in ghcr.io/go-pkgx/packages/… :
//	      response status code 403: denied: requested access to the
//	      resource is denied
//
// which reads as a credentials problem and is not one.
//
// Exported so a caller outside this package can tell them apart; this test
// pins the mapping, including the one that must NOT be an absence.
// ⛔ THE FALSE POSITIVE THAT MADE THIS A TYPE. repoAbsent's last resort
// matches "not found" anywhere in the text, which is safe where it was
// written — it only ever sees the result of a registry call — and wrong
// the moment an exported predicate is pointed at arbitrary errors.
// Measured 2026-10-23 at pkgx's top-level error printer:
//
//	pkgx: command not found in the requested packages: true
//	pkgx: if it should be here: `pkgs request <project>` …
//
// The package was published; the COMMAND was missing. A type cannot be
// matched by accident, and it carries the project so a caller can name it.
func TestATypeCannotBeMatchedByAccident(t *testing.T) {
	// The sentence that fooled the prose test, unchanged.
	stray := errors.New("command not found in the requested packages: true")
	np := &NotPublishedError{
		Project:  "opendev.org/openstack/python-openstackclient",
		Registry: "ghcr.io", Repo: "go-pkgx/packages/opendev.org/…",
		Err: errors.New("403: denied"),
	}

	var got *NotPublishedError
	if errors.As(stray, &got) {
		t.Error("an unrelated 'not found' matched the typed error")
	}
	if !errors.As(np, &got) {
		t.Fatal("the typed error does not match itself")
	}
	if got.Project != "opendev.org/openstack/python-openstackclient" {
		t.Errorf("the project did not survive: %q", got.Project)
	}
	// Wrapped, which is how it reaches a caller.
	if !errors.As(fmt.Errorf("resolving: %w", np), &got) {
		t.Error("the typed error does not survive wrapping")
	}
	// And it still reads the way it always did, since people grep logs.
	if !strings.Contains(np.Error(), "is not published in") {
		t.Errorf("the message changed shape: %q", np.Error())
	}
}

func TestIsNotPublishedSeparatesAbsenceFromFailure(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want bool
	}{
		// ⛔ ONLY THE TYPE CHECK CAN ANSWER THIS ONE: the inner reason is a
		// sentence repoAbsent's prose fallback does not match, so if
		// IsNotPublished stopped consulting the type, this case would turn
		// false. Without it the type branch was covered by nothing — a
		// mutation that deleted it left the suite green.
		{"the typed error, whatever its reason", &NotPublishedError{
			Project: "some.org/thing", Registry: "ghcr.io", Repo: "o/r",
			Err: errors.New("the registry declined to elaborate"),
		}, true},
		{"404 from the registry", &errcode.ErrorResponse{StatusCode: http.StatusNotFound}, true},
		{"oras says not found", errdef.ErrNotFound, true},
		{"name unknown, in prose", errors.New(`ghcr: name unknown: repository name not known to registry`), true},
		// ⛔ The one that must not be swallowed: a registry having a bad day
		// is not a package that does not exist, and treating it as one sends
		// resolution quietly upstream for as long as the upset lasts.
		{"500 from the registry", &errcode.ErrorResponse{StatusCode: http.StatusInternalServerError}, false},
		{"a plain transport failure", errors.New("dial tcp: connection reset by peer"), false},
		{"nothing went wrong", nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.err == nil {
				// IsNotPublished(nil) must not claim an absence.
				if IsNotPublished(nil) {
					t.Error("a nil error was reported as a missing package")
				}
				return
			}
			if got := IsNotPublished(c.err); got != c.want {
				t.Errorf("IsNotPublished(%v) = %v, want %v", c.err, got, c.want)
			}
			// ⛔ The two forms agree on everything a REGISTRY returns —
			// that is the "one rule, not a copy" check. They part company
			// on the typed error ON PURPOSE: the exported form is the one
			// callers reach for, and the type is exactly the precision
			// repoAbsent's prose fallback cannot offer.
			var np *NotPublishedError
			if errors.As(c.err, &np) {
				if repoAbsent(c.err) {
					t.Error("repoAbsent matched the typed error by prose — the type is supposed to be the precise path")
				}
				return
			}
			if IsNotPublished(c.err) != repoAbsent(c.err) {
				t.Errorf("the exported and unexported forms disagree about %v", c.err)
			}
		})
	}
}
