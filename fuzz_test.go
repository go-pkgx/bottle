package bottle

import (
	"strings"
	"testing"
	"unicode"
)

// WHAT SURVIVES PARSING IS SAFE TO PRINT.
//
// That is the invariant the three channel fixes add up to, and it is worth
// a fuzz target rather than a table: a table tests the inputs I thought of,
// and every hole found here so far was in a field I had not thought of.
// There were no Fuzz targets anywhere in this family before this file,
// while bottle parses a catalogue, a lock and a project name — all three
// fetched from somewhere else and all three printed.
//
// The property is deliberately not "it does not panic". It is that a value
// which got PAST the parser cannot carry a cursor movement, because the
// parser is the only place that decides.
func FuzzUnmarshalCatalog(f *testing.F) {
	f.Add(`{"generated":"2026-10-06T15:04:06Z","projects":[{"project":"gnu.org/bash","versions":["5.3"],"platforms":["linux/aarch64"],"provides":["bash"],"summary":"a shell"}]}`)
	f.Add(`{"generated":"","projects":[]}`)
	f.Add(`{"generated":"x","projects":[{"project":"a.org","summary":"\u001b[2K\rspoof","versions":["1.0\u001b[2K"],"platforms":["l\u001b/a"],"provides":["\u0007bell"],"deps":["b.org"]}]}`)
	f.Add(`{"projects":[{"project":"../../etc/passwd"}]}`)
	f.Fuzz(func(t *testing.T, body string) {
		c, err := UnmarshalCatalog([]byte(body))
		if err != nil {
			return
		}
		for _, p := range c.Projects {
			if err := ValidateProjectName(p.Project); err != nil {
				t.Fatalf("a catalogue carried project %q: %v", p.Project, err)
			}
			mustBePrintable(t, "summary of "+p.Project, p.Summary)
			for _, cmd := range p.Provides {
				mustBePrintable(t, "a command of "+p.Project, cmd)
			}
			for _, v := range p.Versions {
				if err := ValidateVersionString(v); err != nil {
					t.Fatalf("a catalogue carried version %q of %s: %v", v, p.Project, err)
				}
			}
			for _, pl := range p.Platforms {
				if err := ValidatePlatformSlug(pl); err != nil {
					t.Fatalf("a catalogue carried platform %q of %s: %v", pl, p.Project, err)
				}
			}
			for _, d := range p.Deps {
				if err := ValidateProjectName(d); err != nil {
					t.Fatalf("%s declares dependency %q: %v", p.Project, d, err)
				}
			}
		}
	})
}

// A lock is the stricter half of the same invariant: nothing is dropped, so
// anything the parser returns was accepted whole.
func FuzzParseLock(f *testing.F) {
	f.Add("lockfile_version = 1\nplatform = \"linux/x86-64\"\nlocked = {\n  \"zlib.net\" = { version = \"1.3.2\", spec = \"sha256:ab\" }\n}\n")
	f.Add("lockfile_version = 99\nlocked = {}\n")
	f.Add("locked = {\n  \"a.org\" = { version = \"1.0\\u001b[2K\\r\", spec = \"\" }\n}\n")
	f.Add("not hcl at all {{{")
	f.Fuzz(func(t *testing.T, body string) {
		d, err := ParseLock([]byte(body), "fuzz.lock.hcl")
		if err != nil {
			// A refusal is printed too, so it is held to the same rule.
			mustBePrintable(t, "the refusal", err.Error())
			return
		}
		if d.Version > LockfileVersion {
			t.Fatalf("a lock from the future parsed: version %d", d.Version)
		}
		if len(d.Pins) == 0 {
			t.Fatal("a lock pinning nothing parsed")
		}
		for _, p := range d.Pins {
			if err := ValidateProjectName(p.Project); err != nil {
				t.Fatalf("a lock carried project %q: %v", p.Project, err)
			}
			if err := ValidateVersionString(p.Version); err != nil {
				t.Fatalf("a lock carried version %q of %s: %v", p.Version, p.Project, err)
			}
			if err := ValidateSpecHash(p.Spec); err != nil {
				t.Fatalf("a lock carried spec %q of %s: %v", p.Spec, p.Project, err)
			}
		}
	})
}

// displayText is the other half: what it returns is SHOWN, so its output is
// the thing that must be printable no matter what went in.
func FuzzDisplayText(f *testing.F) {
	f.Add("a JSON processor", 200)
	f.Add("harmless\x1b[2K\rcurl.se  SAFE", 200)
	f.Add("処理系: 日本語の説明", 200)
	f.Add(strings.Repeat("é", 300), 101)
	f.Add("\x00\x07\x1b  ​", 64)
	f.Fuzz(func(t *testing.T, s string, max int) {
		if max < 0 || max > 1<<16 {
			return
		}
		got := displayText(s, max)
		mustBePrintable(t, "displayText", got)
		if max > 0 && len(got) > max {
			t.Fatalf("displayText returned %d bytes with a limit of %d", len(got), max)
		}
		// Cutting mid-rune is the corruption the limit was meant to
		// prevent, so a replacement character must never be INTRODUCED.
		if strings.ContainsRune(got, '�') && !strings.ContainsRune(s, '�') {
			t.Fatalf("displayText cut mid-rune: %q", got)
		}
	})
}

// mustBePrintable is the one rule, stated once: no control character, no
// DEL, and none of the three Unicode characters that are not controls by
// category yet can still hide or break a line.
func mustBePrintable(t *testing.T, what, s string) {
	t.Helper()
	for i, r := range s {
		switch {
		case r == 0x7f, unicode.IsControl(r):
			t.Fatalf("%s carries %q at byte %d: %q", what, r, i, s)
		case r == '​', r == ' ', r == ' ':
			t.Fatalf("%s carries %q at byte %d: %q", what, r, i, s)
		}
	}
}
