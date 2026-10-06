package bottle

import (
	"strings"
	"testing"
)

// The header of a lock is the only documentation most readers of one will
// ever see: it is in the file, in front of them, at the moment they are
// wondering what to do with it. It advertised `pkgx install --lock`, and
// pkgx has no `install` subcommand — the name was written before the
// command was, and nothing connected the two.
//
// Caught by generating a real lock during the end-to-end check and reading
// what came out, which is the only way a comment's accuracy is ever
// checked.
//
// This test cannot know what pkgx's commands are. What it CAN do is refuse
// the spellings that have already been wrong once, which is what a
// regression test is for.
func TestTheLockHeaderNamesCommandsThatExist(t *testing.T) {
	out := RenderLock(sampleLock())

	for _, wrong := range []string{
		"pkgx install --lock", // pkgx has no `install`
		"bk lock --apply",     // never existed
	} {
		if strings.Contains(out, wrong) {
			t.Errorf("the header advertises %q, which is not a command", wrong)
		}
	}

	// And it still points at the three that do, because a lock whose
	// header says nothing about how to use it is a file people delete.
	for _, right := range []string{
		"bk lock --check",
		"pkgx --lock",
		"bk factory --lock",
	} {
		if !strings.Contains(out, right) {
			t.Errorf("the header no longer mentions %q", right)
		}
	}

	// The header is a comment, so every line of it must be one: a line
	// that lost its `#` would be parsed as HCL and refuse the whole file.
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			break // the header ends at the first blank line
		}
		if !strings.HasPrefix(line, "#") {
			t.Fatalf("a header line is not a comment: %q", line)
		}
	}

	// Proven by the round trip rather than by reading: whatever the header
	// says, the file still parses.
	if _, err := ParseLock([]byte(out), "header.lock.hcl"); err != nil {
		t.Errorf("the rendered lock does not parse: %v", err)
	}
}
