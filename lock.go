package bottle

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// The lock FILE FORMAT: what a lock says, how it is written, how it is read
// back.
//
// # WHY IT LIVES HERE AND NOT IN bk
//
// `bk lock` wrote locks and nothing anywhere could read one back except
// `bk lock --check`, because the reader was in bk's `package main` — which
// is importable by nothing. A format with exactly one program able to read
// it is a format that has not left the program it was written for, and the
// whole point of a lock is that something ELSE acts on it later: `pkgx
// install --lock` is the other end, and it is in another repository.
//
// So the FORMAT moves here, where both ends can reach it, and the
// RESOLUTION stays in bk. That is the real seam: deciding which versions a
// set means today needs a pantry, an overrides set and a version resolver,
// none of which belong in a bottle client. Reading a file that records the
// answer needs none of them.
//
// Writing moves with reading, deliberately. A format whose writer lives in
// one repository and whose reader lives in another is a round trip waiting
// to break on a field one side forgot.

// LockPin is one project as a lock pins it.
//
// Spec is a Merkle hash over the platform, the name, the resolved version,
// the PARSED recipe and the dependencies' spec hashes — Spack's shape. A
// version alone calls two builds the same when a build script changed under
// them.
type LockPin struct{ Project, Version, Spec string }

// Lock is a whole lock: what was asked for, what it resolved to, and the
// facts a later reader needs in order to decide whether the answer still
// holds.
//
// # THE HEADER IS DATA, NOT A COMMENT
//
// The first version of this wrote the platform, the roots and the two
// revisions as `#` lines. They were the right facts in the wrong place: a
// comment cannot be read back, so a check would have had to re-derive them
// from arguments the caller might give differently, and would then be
// checking a different question from the one the file answers.
//
// Spack's lockfile is the precedent for every field. Its `_meta` carries a
// `lockfile-version`; it records the Spack version "to track information
// that should enhance reproducibility"; and its top level holds `roots`
// beside `concrete_specs`.
type Lock struct {
	Version   int    // lockfile_version
	Platform  string // the platform it was taken on: it CHANGES the answer
	Generated string // RFC3339, UTC
	BK        string // which bk wrote it
	Roots     []string
	Pantry    string
	Overlay   string
	Pins      []LockPin
}

// LockfileVersion is this format's number. Bumped when a reader of the
// previous one would MISREAD a file rather than merely miss a field.
//
// The compatibility rule is Spack's, and worth copying: new readers read
// old locks, old readers refuse new ones.
const LockfileVersion = 1

// RenderLock writes a lock. HCL, because every other file this ecosystem
// reads by hand is HCL and HCLToMap reads it straight back.
func RenderLock(d Lock) string {
	var b strings.Builder
	b.WriteString("# bk lock\n#\n" +
		"# `spec` is a Merkle hash over the platform, the name, the resolved\n" +
		"# version, the PARSED recipe (so reformatting does not move it) and the\n" +
		"# spec hashes of the dependencies — Spack's shape, whose packaging guide\n" +
		"# counts \"a canonical hash of the package.py recipes\" among a spec hash's\n" +
		"# inputs. A version alone calls two builds the same when a build script\n" +
		"# changed under them.\n#\n" +
		"# What this still does NOT pin: the BYTES of the built bottle. The spec\n" +
		"# hash covers the inputs, as Nix's and Spack's do; an output digest is a\n" +
		"# different promise and is not made here.\n#\n" +
		"# Sorted by project, not in build order: a lock is read as a diff, and a\n" +
		"# topological order makes every line move when one dependency does.\n#\n" +
		"# `bk lock --check <this file>` re-resolves and says what moved.\n" +
		"# `pkgx --lock <this file>` runs exactly these versions, and\n" +
		"# `bk factory --lock <this file>` builds them.\n\n")
	fmt.Fprintf(&b, "lockfile_version = %d\n", d.Version)
	fmt.Fprintf(&b, "bk               = %q\n", d.BK)
	fmt.Fprintf(&b, "platform         = %q\n", d.Platform)
	fmt.Fprintf(&b, "generated        = %q\n", d.Generated)
	fmt.Fprintf(&b, "pantry           = %q\n", d.Pantry)
	fmt.Fprintf(&b, "overlay          = %q\n", d.Overlay)
	b.WriteString("roots            = [")
	for i, r := range d.Roots {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%q", r)
	}
	b.WriteString("]\n\nlocked = {\n")
	for _, p := range d.Pins {
		fmt.Fprintf(&b, "  %q = { version = %q, spec = %q }\n", p.Project, p.Version, p.Spec)
	}
	b.WriteString("}\n")
	return b.String()
}

// ReadLock parses a lock from a file.
func ReadLock(path string) (Lock, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return Lock{}, err
	}
	return ParseLock(src, path)
}

// ParseLock parses a lock from bytes. path is used only in error messages,
// so a caller that already has the content — a test, or a tool reading from
// a pipe — does not have to put it on disk first.
//
// Through HCLToMap, the same reader the pantry overlay's HCL recipes go
// through, so the lock cannot develop a dialect of its own.
func ParseLock(src []byte, path string) (Lock, error) {
	m, err := HCLToMap(src, path)
	if err != nil {
		return Lock{}, err
	}
	d := Lock{
		Version:   int(lockInt(m["lockfile_version"])),
		Platform:  lockString(m["platform"]),
		Generated: lockString(m["generated"]),
		BK:        lockString(m["bk"]),
		Pantry:    lockString(m["pantry"]),
		Overlay:   lockString(m["overlay"]),
	}
	for _, r := range lockSlice(m["roots"]) {
		d.Roots = append(d.Roots, lockString(r))
	}
	// A lock with no readable `locked` block is not an empty lock. An error
	// for the same reason `bk lock` refuses to pin nothing: the caller
	// would read "nothing moved" off a file that says nothing.
	locked, ok := m["locked"].(map[string]any)
	if !ok || len(locked) == 0 {
		return Lock{}, fmt.Errorf("%s: no `locked` entries — this is not a lock", path)
	}
	for proj, v := range locked {
		e, ok := v.(map[string]any)
		if !ok {
			return Lock{}, fmt.Errorf("%s: %q is not a { version = …, spec = … } entry", path, proj)
		}
		d.Pins = append(d.Pins, LockPin{proj, lockString(e["version"]), lockString(e["spec"])})
	}
	sort.Slice(d.Pins, func(i, j int) bool { return d.Pins[i].Project < d.Pins[j].Project })
	if d.Version > LockfileVersion {
		return Lock{}, fmt.Errorf("%s: lockfile_version %d, and this build understands %d — "+
			"read it with a newer one rather than with this, which would miss whatever the "+
			"bump was for", path, d.Version, LockfileVersion)
	}
	return d, nil
}

// LockAge says how old a lock is, in the words every other age in this
// ecosystem is said in.
func LockAge(generated string, now time.Time) string {
	t, err := time.Parse(time.RFC3339, generated)
	if err != nil {
		return "unknown age"
	}
	d := now.UTC().Sub(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d minute(s) old", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hour(s) old", int(d.Hours()))
	}
	return fmt.Sprintf("%d day(s) old", int(d.Hours()/24))
}

// lockString, lockInt and lockSlice read a value HCLToMap produced. They do
// not report a type error: a field of the wrong type reads as its zero, and
// a comparison then SAYS so by name instead of refusing the whole file over
// one line. The one shape that cannot be tolerated — a missing `locked` —
// is checked in ParseLock.
func lockString(v any) string {
	s, _ := v.(string)
	return s
}

func lockInt(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case float64:
		return int64(n)
	}
	return 0
}

func lockSlice(v any) []any {
	s, _ := v.([]any)
	return s
}
