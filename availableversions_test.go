package bottle

import (
	"strings"
	"testing"
)

// ⛔ A COUNT IS NOT AN ANSWER, AND THIS ONE READ AS A VERSION. The message
// used to end "(available: 1)", which beside a constraint of "=1.7.1" reads
// as a claim about version 1 — measured 2026-10-08 on the author of the
// sentence, seconds after writing it. A count also withholds the one fact
// that ends the problem: WHICH versions exist.
func TestAvailableVersionsNamesThemNewestFirst(t *testing.T) {
	vs := []Ver{ParseVer("1.6.0"), ParseVer("1.7.1"), ParseVer("1.8.2")}
	got := availableVersions(vs)
	if got != "1.8.2 1.7.1 1.6.0" {
		t.Errorf("availableVersions = %q, want newest first", got)
	}
	// ⛔ THE REGRESSION ITSELF: a bare count, which is what this replaces.
	if got == "3" {
		t.Errorf("still a count: %q", got)
	}
}

// A PROJECT CAN CARRY HUNDREDS, so the list is capped — but the total is
// still stated, because "six versions" and "six hundred" are different
// problems and the reader must be able to tell them apart.
func TestAvailableVersionsCapsTheListAndSaysTheTotal(t *testing.T) {
	var vs []Ver
	for i := 0; i < 40; i++ {
		vs = append(vs, ParseVer("1.0."+string(rune('0'+i%10))))
	}
	got := availableVersions(vs)
	// Count the VERSIONS, not the spaces: the "… (40 in all)" tail has
	// spaces of its own, and counting those measured the suffix instead of
	// the cap it was meant to check.
	listed, _, _ := strings.Cut(got, " … ")
	if n := len(strings.Fields(listed)); n != 6 {
		t.Errorf("listed %d versions, want 6: %q", n, got)
	}
	if !strings.Contains(got, "40 in all") {
		t.Errorf("the total is missing: %q", got)
	}
}

// AN EMPTY LIST SAYS SO. "available: " with nothing after it reads as a
// truncated message rather than an answer.
func TestAvailableVersionsOfNoneSaysSo(t *testing.T) {
	if got := availableVersions(nil); got != "none" {
		t.Errorf("availableVersions(nil) = %q, want none", got)
	}
}

// AND THE SENTENCE ITSELF, through the real resolver against a real listing:
// a unit test on the helper cannot show that the helper is actually reached.
func TestUnsatisfiableConstraintNamesTheVersionsItHas(t *testing.T) {
	up, _ := upstreamVersionsServer(t, "plain.org", "linux", "aarch64", []string{"1.0.0", "1.1.0"})
	oldDist := DistBase
	DistBase = up
	defer func() { DistBase = oldDist }()

	_, err := PickVersionForAll("plain.org", []string{"=9.9.9"}, "linux", "aarch64")
	if err == nil {
		t.Fatal("a constraint nothing satisfies resolved")
	}
	got := err.Error()
	if !strings.Contains(got, "1.1.0") || !strings.Contains(got, "1.0.0") {
		t.Errorf("the versions it does have are not named: %q", got)
	}
	if strings.Contains(got, "available: 2") {
		t.Errorf("still a count: %q", got)
	}
}
