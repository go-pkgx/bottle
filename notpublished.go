package bottle

import (
	"errors"
	"fmt"
)

// NotPublishedError says that THIS registry does not carry a project, and
// says which project, so a caller can act rather than parse.
//
// # WHY A TYPE AND NOT A SENTENCE
//
// ⛔ BECAUSE THE PROSE TEST IS TOO WIDE ONCE IT LEAVES THIS PACKAGE.
// repoAbsent's last resort matches `not found` anywhere in an error's text,
// which is safe where it was written — it only ever sees the result of a
// registry call — and wrong as soon as an exported predicate is pointed at
// arbitrary errors. Measured 2026-10-23, the first use of the exported
// IsNotPublished at pkgx's top-level error printer:
//
//	pkgx: command not found in the requested packages: true
//	pkgx: if it should be here: `pkgs request <project>` …
//
// The package was published; the COMMAND was not there. The hint fired on
// the word "not found" in an unrelated sentence.
//
// A type cannot be matched by accident, and it carries the project — so a
// caller can name it instead of printing a placeholder and hoping the
// reader fills it in from the line above.
type NotPublishedError struct {
	Project  string
	Registry string
	Repo     string
	Err      error
}

func (e *NotPublishedError) Error() string {
	return fmt.Sprintf("%s is not published in %s/%s (%v)", e.Project, e.Registry, e.Repo, e.Err)
}

func (e *NotPublishedError) Unwrap() error { return e.Err }

// IsNotPublished reports whether err means this registry simply does not
// carry the project, as opposed to a transient or authentication failure.
//
// ⛔ IT IS ABOUT AN ERROR FROM A REGISTRY CALL. The typed form above is
// exact; the fallback is repoAbsent, whose last resort reads the error's
// TEXT, and text written for another purpose can contain "not found". Pass
// it what came back from the registry, not whatever reached your error
// printer — or match *NotPublishedError yourself and be sure.
func IsNotPublished(err error) bool {
	var np *NotPublishedError
	if errors.As(err, &np) {
		return true
	}
	return repoAbsent(err)
}
