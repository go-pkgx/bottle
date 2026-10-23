package bottle

import (
	"errors"
	"net/http"
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
func TestIsNotPublishedSeparatesAbsenceFromFailure(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want bool
	}{
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
			// And it is the same rule as the unexported one, not a copy.
			if IsNotPublished(c.err) != repoAbsent(c.err) {
				t.Errorf("the exported and unexported forms disagree about %v", c.err)
			}
		})
	}
}
