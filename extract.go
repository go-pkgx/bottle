// Copyright (c) 2026, the go-pkgx/bottle authors
// All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package bottle

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// ErrInsecurePath is returned by Extract when an archive entry (or a hard-link
// source) names an absolute path, or one that after component-stripping would
// escape the destination directory. It is wrapped with the offending name so
// callers can test for it with errors.Is.
var ErrInsecurePath = errors.New("bottle: insecure path in archive")

// osWriteFlags is how extracted regular files are opened.
const osWriteFlags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC

// Injectable seams over the os operations whose error branches are otherwise
// unreachable in a test (a syscall that succeeds and only later fails is not
// reproducible with real files). Tests override these to exercise every
// error-handling path; production uses the real functions verbatim.
var (
	extMkdirAll = os.MkdirAll
	extSymlink  = os.Symlink
	extLink     = os.Link
	extOpenFile = os.OpenFile
	extChtimes  = os.Chtimes
	extCopy     = io.Copy
)

// Extract unpacks every entry of tr into dest, stripping strip leading path
// components from each entry name (strip == 0 keeps the archive layout). It is
// the shared archive extractor for the pkgx ecosystem — both bottle's bottle
// installer and bk's source fetcher route through it, so a single implementation
// carries the invariants both rely on:
//
//   - Regular files keep the modification time the archive recorded (tar(1)
//     semantics). Recipes DEPEND on this: a release tarball ships generated
//     files NEWER than the sources they derive from so make leaves them alone;
//     stamping every file "now" re-orders them by archive position and make then
//     tries to regenerate — libexpat 2.8.3 dies that way (doc/xmlwf.1 is archived
//     before, hence would be stamped older than, doc/xmlwf.xml → make runs the
//     docbook rule with no docbook2x-man installed → Error 1). A zero recorded
//     time is left as written.
//   - Absolute names, and names that escape dest after stripping, are rejected
//     with ErrInsecurePath; a hard-link source is vetted the same way.
//   - Directories, regular files, symlinks and hard links are reproduced;
//     unsupported entry types (fifos, devices, ...) are skipped.
//
// tar.ErrInsecurePath from tr.Next is tolerated because Extract performs its own
// stricter vetting on every entry name.
func Extract(tr *tar.Reader, dest string, strip int) error {
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil && !errors.Is(err, tar.ErrInsecurePath) {
			return err
		}
		target, ok, err := extSafeTarget(dest, hdr.Name, strip)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		mode := hdr.FileInfo().Mode()
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := extMkdirAll(target, extPermOr(mode, 0o755)); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := extMkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := extSymlink(hdr.Linkname, target); err != nil {
				return err
			}
		case tar.TypeLink:
			if err := extMkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			source, err := extLinkSource(dest, hdr.Linkname)
			if err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := extLink(source, target); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := extMkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := extWriteFile(target, extPermOr(mode, 0o644), tr); err != nil {
				return err
			}
			if err := extRestoreTime(target, hdr.ModTime); err != nil {
				return err
			}
		}
	}
}

// extSafeTarget resolves an archive entry name to a path under dest after
// stripping strip leading components. ok is false when the entry is fully
// consumed by stripping (nothing to write). An absolute name, or one that
// escapes dest, yields ErrInsecurePath.
func extSafeTarget(dest, name string, strip int) (target string, ok bool, err error) {
	if path.IsAbs(name) || filepath.IsAbs(filepath.FromSlash(name)) {
		return "", false, fmt.Errorf("%w: %q", ErrInsecurePath, name)
	}
	parts := strings.Split(path.Clean(name), "/")
	if len(parts) <= strip {
		return "", false, nil
	}
	rel := path.Join(parts[strip:]...)
	if rel == "." {
		return "", false, nil
	}
	target = filepath.Join(dest, filepath.FromSlash(rel))
	prefix := filepath.Clean(dest) + string(filepath.Separator)
	if !strings.HasPrefix(target+string(filepath.Separator), prefix) {
		return "", false, fmt.Errorf("%w: %q", ErrInsecurePath, name)
	}
	return target, true, nil
}

// extLinkSource resolves a hard-link source name to a path under dest, applying
// the same safety vetting as extSafeTarget (a hard link may not point outside
// the extraction root).
func extLinkSource(dest, linkname string) (string, error) {
	if path.IsAbs(linkname) || filepath.IsAbs(filepath.FromSlash(linkname)) {
		return "", fmt.Errorf("%w: link %q", ErrInsecurePath, linkname)
	}
	source := filepath.Join(dest, filepath.FromSlash(path.Clean(linkname)))
	prefix := filepath.Clean(dest) + string(filepath.Separator)
	if !strings.HasPrefix(source+string(filepath.Separator), prefix) {
		return "", fmt.Errorf("%w: link %q", ErrInsecurePath, linkname)
	}
	return source, nil
}

// extPermOr returns the permission bits of m, or fallback when m carries none
// (e.g. archive entries written without Unix modes).
func extPermOr(m, fallback fs.FileMode) fs.FileMode {
	if p := m.Perm(); p != 0 {
		return p
	}
	return fallback
}

// extWriteFile creates target with perm and copies r into it.
func extWriteFile(target string, perm fs.FileMode, r io.Reader) error {
	f, err := extOpenFile(target, osWriteFlags, perm)
	if err != nil {
		return err
	}
	if _, err := extCopy(f, r); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// extRestoreTime stamps path with the archive's recorded modification time; a
// zero time (no record) is left as written.
func extRestoreTime(path string, mt time.Time) error {
	if mt.IsZero() {
		return nil
	}
	return extChtimes(path, mt, mt)
}
