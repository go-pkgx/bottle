package bottle

import (
	"slices"
	"strings"
	"testing"
)

// ⛔⛔ THE LIBRARY'S DEFAULT IS NOT EMPTY, which is the whole point of this
// file. The ranking failed to reach the fleet twice by being inert: first
// behind an environment variable nobody set, then behind an activation that
// lived in one module's `internal` package. A default that starts empty is the
// same defect waiting for the next binary.
func TestTheLibraryCarriesTheListWithoutAnyActivation(t *testing.T) {
	if len(DefaultDeprecated) == 0 {
		t.Fatal("DefaultDeprecated is empty, so the EOL ranking is inert again")
	}
	if len(DefaultDeprecated["openssl.org"]) == 0 {
		t.Error("openssl.org has no deprecated lines, which is what this was built for")
	}
}

// ⛔ A LINE CANNOT BE BOTH. Listing a line that is still supported is the
// expensive mistake: it would push `^3` off the 3.5 LTS onto something older,
// quietly, with no error anywhere. Both halves of the measurement are
// recorded so that edit fails here instead of shipping.
func TestNoSupportedLineIsListedAsDeprecated(t *testing.T) {
	for project, supported := range KnownSupported {
		for _, line := range supported {
			if slices.Contains(KnownDeprecated[project], line) {
				t.Errorf("%s %s is listed as BOTH supported and deprecated", project, line)
			}
		}
	}
}

// Every project named in one half must be named in the other: a project with
// deprecated lines and no recorded supported line has had only half its
// verdict written down, and nothing would catch the day its last supported
// line is deprecated too.
func TestBothHalvesCoverTheSameProjects(t *testing.T) {
	for project := range KnownDeprecated {
		if len(KnownSupported[project]) == 0 {
			t.Errorf("%s has deprecated lines but no supported ones recorded", project)
		}
	}
	for project := range KnownSupported {
		if _, ok := KnownDeprecated[project]; !ok {
			t.Errorf("%s has supported lines but no deprecated ones recorded", project)
		}
	}
}

// The date is a fact a reader needs, and a list with no date reads as fresh
// forever.
func TestTheListIsDated(t *testing.T) {
	if len(strings.Split(KnownDeprecatedAsOf, "-")) != 3 {
		t.Errorf("KnownDeprecatedAsOf = %q, want YYYY-MM-DD", KnownDeprecatedAsOf)
	}
}

// ⛔ EVERY LINE IS A PREFIX OF A REAL VERSION STRING, not a version itself.
// `deprecatedLine` matches a raw version against these by line, so "3.6" must
// cover 3.6.4 while "3.6.4" would cover only itself — writing a full version
// here would silently narrow the list to one release.
func TestTheListHoldsLinesNotVersions(t *testing.T) {
	for project, lines := range KnownDeprecated {
		for _, line := range lines {
			if n := len(strings.Split(line, ".")); n > 3 {
				t.Errorf("%s %q has %d components: a LINE, not a version", project, line, n)
			}
		}
	}
}
