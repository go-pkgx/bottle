package bottle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/ulikunitz/xz"
	yaml "gopkg.in/yaml.v3"
)

// Base URLs for the pkgx distribution + pantry; overridable in tests, and at
// runtime via $PKGX_DIST / $PKGX_PANTRY so a consumer can point pkgm/pkgx at a
// local mirror produced by the `mirror` tool.
//
// DistBase defaults to the **signed** go-pkgx OCI registry so the default install
// path is verifiable end-to-end (pairs with VerifyRequired defaulting on). That
// registry is a growing subset of the pantry; for the full upstream catalogue set
// PKGX_DIST=https://dist.pkgx.dev (unsigned → also set PKGX_VERIFY=0).
var (
	DistBase   = "oci://ghcr.io/go-pkgx/packages"
	PantryBase = "https://raw.githubusercontent.com/pkgxdev/pantry/main/projects"

	// PantryOverlay (PKGX_PANTRY_OVERLAY), when set, is consulted for a project's
	// package.yml BEFORE PantryBase, falling back to PantryBase when the overlay
	// has no recipe for that project. This lets a small curated overlay carry
	// corrected recipes (e.g. a stale `openssl.org: ^1.1` bumped to a modern
	// constraint that matches the published bottles) without forking the whole
	// pantry — everything the overlay does not override resolves upstream.
	PantryOverlay = ""

	// UpstreamDist is the canonical pkgx distribution used to list versions for
	// projects that are not (yet) published to an OCI DistBase — typically
	// build-time deps such as llvm.org, perl.org or qt.io. It mirrors what
	// `pkgx +<pkg>` installs, so a {{deps.<p>.prefix}} token resolves to the same
	// version pkgx actually installs at build time. Overridable in tests.
	UpstreamDist = "https://dist.pkgx.dev"
)

func init() { applyEnv(Env) }

// ociClientCache memoises OCIClients by dist base so the bearer-token cache is
// reused across calls (and rebuilds automatically when DistBase changes, e.g. in
// tests or when a consumer re-points PKGX_DIST).
var (
	ociClientCache = map[string]*OCIClient{}
	ociClientMu    sync.Mutex
)

// ociClientForDist returns the OCIClient for the current DistBase, cached.
func ociClientForDist() (*OCIClient, error) {
	ociClientMu.Lock()
	defer ociClientMu.Unlock()
	if c, ok := ociClientCache[DistBase]; ok {
		return c, nil
	}
	c, err := NewOCIClient(DistBase)
	if err != nil {
		return nil, err
	}
	ociClientCache[DistBase] = c
	return c, nil
}

// applyEnv overrides DistBase/PantryBase from PKGX_DIST/PKGX_PANTRY (testable).
func applyEnv(get func(string) string) {
	if d := get("PKGX_DIST"); d != "" {
		DistBase = strings.TrimRight(d, "/")
	}
	if p := get("PKGX_PANTRY"); p != "" {
		PantryBase = strings.TrimRight(p, "/")
	}
	if p := get("PKGX_PANTRY_OVERLAY"); p != "" {
		PantryOverlay = strings.TrimRight(p, "/")
	}
}

// fetchRecipe returns a project's package.yml, trying PantryOverlay first (when
// set) and falling back to PantryBase when the overlay lacks that project.
func fetchRecipe(project string) ([]byte, error) {
	if PantryOverlay != "" {
		if body, err := httpGet(fmt.Sprintf("%s/%s/package.yml", PantryOverlay, project)); err == nil {
			return body, nil
		}
	}
	return httpGet(fmt.Sprintf("%s/%s/package.yml", PantryBase, project))
}

// Dir resolves the bottle store (PKGX_DIR, default ~/.pkgx).
func Dir() string {
	if d := Env("PKGX_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".pkgx")
}

// HostSlug returns the pkgx (os, arch) slug for the running machine.
func HostSlug() (string, string) {
	return goos(), goarch()
}

// --- version type + constraint matching ------------------------------------

// Ver is a parsed pkgx version: its numeric components plus the raw string.
//
// Tag is the registry tag the version was found under, when that differs from
// Raw — a glibc-flavored build lives at `<version>-glibc<ver>` while remaining
// version <version>. Everything version-shaped (comparison, constraints, the
// installed v<version> prefix) uses Raw; only the registry pull uses the tag.
type Ver struct {
	Raw  string
	Nums []int
	Tag  string
}

// tag is the registry tag to pull this version from.
func (v Ver) tag() string {
	if v.Tag != "" {
		return v.Tag
	}
	return v.Raw
}

// ParseVer parses a pkgx version string into a Ver, stopping each component at
// the first non-numeric character (e.g. "1w" in openssl 1.1.1w).
func ParseVer(s string) Ver {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	parts := strings.Split(s, ".")
	v := Ver{Raw: s}
	for _, p := range parts {
		// stop at first non-numeric segment (e.g. "1w" in openssl 1.1.1w)
		n := 0
		i := 0
		for i < len(p) && p[i] >= '0' && p[i] <= '9' {
			n = n*10 + int(p[i]-'0')
			i++
		}
		v.Nums = append(v.Nums, n)
	}
	return v
}

func cmpVer(a, b Ver) int {
	for i := 0; i < len(a.Nums) || i < len(b.Nums); i++ {
		var x, y int
		if i < len(a.Nums) {
			x = a.Nums[i]
		}
		if i < len(b.Nums) {
			y = b.Nums[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// satisfies reports whether version v meets a pkgx constraint string.
// Supported: "" / "*" (any), "^A.B.C" (>=, same major), "~A.B.C" (>=, same
// major.minor), the range operators ">=", ">", "<=", "<", an exact "=A.B.C",
// and a bare "A.B.C" (treated as a caret-style lower bound so partial pins like
// "1" or "1.1" match a whole line). The upper-bound operators "<"/"<=" are what
// build-dep pins such as `llvm.org: <19` use.
func (v Ver) satisfies(c string) bool {
	c = strings.TrimSpace(strings.Trim(c, "'\""))
	if c == "" || c == "*" {
		return true
	}
	op := "^"
	switch { // longer operators first so ">=" beats ">" and "<=" beats "<"
	case strings.HasPrefix(c, ">="):
		op, c = ">=", strings.TrimSpace(c[2:])
	case strings.HasPrefix(c, "<="):
		op, c = "<=", strings.TrimSpace(c[2:])
	case strings.HasPrefix(c, ">"):
		op, c = ">", strings.TrimSpace(c[1:])
	case strings.HasPrefix(c, "<"):
		op, c = "<", strings.TrimSpace(c[1:])
	case strings.HasPrefix(c, "^"):
		op, c = "^", c[1:]
	case strings.HasPrefix(c, "~"):
		op, c = "~", c[1:]
	case strings.HasPrefix(c, "="):
		op, c = "=", c[1:]
	}
	base := ParseVer(c)
	switch op {
	case ">=":
		return cmpVer(v, base) >= 0
	case ">":
		return cmpVer(v, base) > 0
	case "<=":
		return cmpVer(v, base) <= 0
	case "<":
		return cmpVer(v, base) < 0
	case "=":
		return cmpVer(v, base) == 0
	case "~":
		if cmpVer(v, base) < 0 {
			return false
		}
		// ~ pins all-but-the-last specified component: ~2 -> major, ~2.6 and
		// ~2.6.3 -> major.minor. Pin count = len(base) capped at 2.
		n := len(base.Nums)
		if n > 2 {
			n = 2
		}
		return sameN(v, base, n)
	default: // "^" and bare
		if cmpVer(v, base) < 0 {
			return false
		}
		return sameN(v, base, 1)
	}
}

// sameN reports whether the first n version components match.
func sameN(v, base Ver, n int) bool {
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(v.Nums) {
			x = v.Nums[i]
		}
		if i < len(base.Nums) {
			y = base.Nums[i]
		}
		if x != y {
			return false
		}
	}
	return true
}

// --- network ----------------------------------------------------------------

func httpGet(url string) ([]byte, error) {
	resp, err := HTTPClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// FetchVersions returns the available versions of a project for the host
// os/arch, ascending.
func FetchVersions(project string) ([]Ver, error) {
	osn, arch := HostSlug()
	return VersionsFor(project, osn, arch)
}

// VersionsFor returns the available versions of a project for an explicit pkgx
// os/arch slug (e.g. "linux"/"aarch64"), ascending. Used by mirror tooling that
// spans arches other than the host's.
//
// When DistBase is an OCI registry (the factory default), version listing comes
// from that registry's tags. That registry is a growing subset of the upstream
// catalogue, so build-time deps (e.g. llvm.org, perl.org) may not be published
// there yet and list zero versions. In that case we fall back to the upstream
// pkgx dist so dep resolution matches the version `pkgx +<pkg>` installs at build
// time — the actual bottle *pull* still goes through DistBase unchanged, so this
// only affects version listing, not the install source.
func VersionsFor(project, osn, arch string) ([]Ver, error) {
	if IsOCI(DistBase) {
		vs, err := ociVersionsFor(project)
		if err != nil {
			// A project we have never published isn't a repository in our
			// registry at all — ghcr answers the tag listing with 404
			// NAME_UNKNOWN. That is the same "not carried here" case as an empty
			// list (a build-dep like rust-lang.org/curl.se/python.org), so fall
			// back to the upstream dist rather than failing the whole recipe.
			// Genuine transient/auth errors still propagate.
			if repoAbsent(err) {
				return httpVersionsFor(UpstreamDist, project, osn, arch)
			}
			return nil, err
		}
		if len(vs) > 0 {
			return vs, nil
		}
		return httpVersionsFor(UpstreamDist, project, osn, arch)
	}
	return httpVersionsFor(DistBase, project, osn, arch)
}

// repoAbsent reports whether err signals that the OCI registry simply does not
// carry the project (ghcr returns HTTP 404 with "name unknown: repository name
// not known to registry"), as opposed to a transient or auth error that should
// propagate.
func repoAbsent(err error) bool {
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "name unknown") ||
		strings.Contains(s, "not known to registry") ||
		strings.Contains(s, "not found") ||
		strings.Contains(s, "404") {
		return true
	}
	// ghcr does not answer 404 for a repository that does not exist: an
	// ANONYMOUS token request for it is denied with 403, indistinguishable from
	// "exists but you may not read it". For a public registry read without
	// credentials the useful reading is "we do not carry this package" — so fall
	// back to upstream, exactly as an empty listing would. With credentials
	// configured a 403 IS an access problem and must surface: masking it would
	// hide a broken token behind silently different resolution.
	return anonymousRead() && strings.Contains(s, "403")
}

// anonymousRead reports whether the registry is being read with no credentials
// at all (no OCI_TOKEN, no OCI_USERNAME/OCI_PASSWORD).
func anonymousRead() bool {
	return Env("OCI_TOKEN") == "" && Env("OCI_USERNAME") == "" && Env("OCI_PASSWORD") == ""
}

// httpVersionsFor lists a project's versions from a static pkgx dist tree's
// per-arch versions.txt, ascending.
func httpVersionsFor(base, project, osn, arch string) ([]Ver, error) {
	body, err := httpGet(fmt.Sprintf("%s/%s/%s/%s/versions.txt", base, project, osn, arch))
	if err != nil {
		return nil, err
	}
	var vs []Ver
	for _, line := range strings.Fields(string(body)) {
		vs = append(vs, ParseVer(line))
	}
	sort.Slice(vs, func(i, j int) bool { return cmpVer(vs[i], vs[j]) < 0 })
	return vs, nil
}

// ociVersionsFor lists a project's versions from an OCI registry (the repo's
// tags), ascending. The tag list is not per-arch — a version that lacks a bottle
// for the requested platform simply fails at download time, mirroring how the
// static tree 404s a missing per-arch tarball.
func ociVersionsFor(project string) ([]Ver, error) {
	c, err := ociClientForDist()
	if err != nil {
		return nil, err
	}
	tags, err := c.ListTags(project)
	if err != nil {
		return nil, err
	}
	return selectVersions(tags, GlibcFlavor()), nil
}

// selectVersions turns a registry tag listing into the candidate versions for a
// host, ascending.
//
// A glibc-flavored tag (<version>-glibc<ver>) is one BUILD of a version, not a
// version of its own: it must never outrank the plain tag it flavors
// (2.0-glibc2.27.0 parses as 2.0.0.2.27.0 > 2.0). So flavors are matched
// DELIBERATELY — a host that pinned PKGX_GLIBC takes the build made against that
// glibc, every other flavor is ignored, and the result is independent of the
// order the registry happens to list tags in.
// numericKey is a version's canonical numeric identity: "2.44" and "2.44.0"
// share one, since cmpVer already treats them as the same version.
func numericKey(v Ver) string {
	n := len(v.Nums)
	for n > 1 && v.Nums[n-1] == 0 {
		n-- // trailing zeros carry no information
	}
	parts := make([]string, n)
	for i := 0; i < n; i++ {
		parts[i] = strconv.Itoa(v.Nums[i])
	}
	return strings.Join(parts, ".")
}

// supersedes reports whether candidate v should replace the one already kept for
// the same numeric version: a flavored build always wins (it was asked for), and
// otherwise the MORE SPECIFIC spelling does, so the choice never depends on the
// order the registry happened to list its tags in.
func supersedes(v, prev Ver, flavor string) bool {
	if prev.Tag != "" {
		return false // a flavored build is already held
	}
	if flavor != "" {
		return true
	}
	if len(v.Nums) != len(prev.Nums) {
		return len(v.Nums) > len(prev.Nums)
	}
	return v.Raw > prev.Raw
}

func selectVersions(tags []string, wantFlavor string) []Ver {
	byVersion := map[string]Ver{}
	for _, t := range tags {
		if !isVersionTag(t) {
			continue
		}
		ver, flavor := SplitFlavor(t)
		if flavor != "" && flavor != wantFlavor {
			continue // built against some other glibc: never ours
		}
		// Key on the NUMERIC version, so "1.0.0", "v1.0.0" and "1.0" are one
		// version. They compare equal, so leaving them as separate candidates
		// makes the pick depend on the registry's listing order — and our own
		// registry does carry both spellings (gnu.org/glibc has a 2.44 tag from a
		// factory build and a 2.44.0 tag from the upstream mirror). A build then
		// installed BOTH glibc trees side by side and linked against a sysroot
		// that was not the one its loader came from.
		v := ParseVer(ver)
		key := numericKey(v)
		if prev, ok := byVersion[key]; ok && !supersedes(v, prev, flavor) {
			continue
		}
		if flavor != "" {
			v.Tag = t
		}
		byVersion[key] = v
	}
	vs := make([]Ver, 0, len(byVersion))
	for _, v := range byVersion {
		vs = append(vs, v)
	}
	sort.Slice(vs, func(i, j int) bool { return cmpVer(vs[i], vs[j]) < 0 })
	return vs
}

// isVersionTag reports whether a registry tag names a package VERSION rather
// than registry bookkeeping.
//
// This matters because ghcr implements no referrers API, so ORAS keeps each
// bottle's attestations under a fallback tag named `sha256-<digest>`: those tags
// sit in the same listing as the versions. Parsed as versions they became
// phantom "0" entries — inflating every count, and (worse) making a listing
// look non-empty so the upstream-dist fallback never engaged for a project we
// had published only some versions of.
func isVersionTag(tag string) bool {
	s := strings.TrimPrefix(strings.TrimPrefix(tag, "v"), "V")
	return s != "" && s[0] >= '0' && s[0] <= '9'
}

// PickVersion returns the highest available version satisfying constraint.
func PickVersion(project, constraint string) (Ver, error) {
	vs, err := FetchVersions(project)
	if err != nil {
		return Ver{}, err
	}
	for i := len(vs) - 1; i >= 0; i-- {
		if vs[i].satisfies(constraint) {
			return vs[i], nil
		}
	}
	return Ver{}, fmt.Errorf("no version of %s satisfies %q (available: %d)", project, constraint, len(vs))
}

// Satisfies reports whether the version meets a pkgx constraint
// ("^1.2", "~2", ">=1.0", "=1.2.3", "*", or "").
func (v Ver) Satisfies(constraint string) bool { return v.satisfies(constraint) }

// DownloadBottle fetches the raw compressed bottle tarball for a specific
// project/version/os/arch, trying .tar.gz then .tar.xz. It returns the bytes
// and the extension that succeeded (".tar.gz" or ".tar.xz") — for mirror tooling
// that copies bottles verbatim without extracting them.
func DownloadBottle(project, ver, osn, arch string) ([]byte, string, error) {
	if IsOCI(DistBase) {
		c, err := ociClientForDist()
		if err != nil {
			return nil, "", err
		}
		data, ext, err := c.Pull(project, ver, osn, arch)
		if err != nil {
			return nil, "", err
		}
		if VerifyRequired() {
			if err := c.VerifyBottle(project, ver, osn, arch, data); err != nil {
				return nil, "", fmt.Errorf("verify %s v%s (%s/%s): %w", project, ver, osn, arch, err)
			}
		}
		return data, ext, nil
	}
	// The static-HTTP transport carries no signatures (referrers are OCI-only);
	// if verification is demanded we cannot satisfy it, so fail closed.
	if VerifyRequired() {
		return nil, "", fmt.Errorf("signature verification is on by default but PKGX_DIST=%s (HTTP) has no signatures; use an oci:// dist or set PKGX_VERIFY=0", DistBase)
	}
	base := fmt.Sprintf("%s/%s/%s/%s/v%s", DistBase, project, osn, arch, ver)
	for _, ext := range []string{ExtTarGz, ExtTarXz} {
		resp, err := HTTPClient.Get(base + ext)
		if err != nil {
			return nil, "", err
		}
		if resp.StatusCode == 200 {
			data, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return nil, "", err
			}
			return data, ext, nil
		}
		resp.Body.Close()
	}
	return nil, "", fmt.Errorf("no bottle for %s v%s (%s/%s)", project, ver, osn, arch)
}

// --- package.yml (dependencies + provides) ----------------------------------

type pkgYML struct {
	Dependencies map[string]yaml.Node `yaml:"dependencies"`
	Provides     yaml.Node            `yaml:"provides"`
}

// FetchMeta returns the host-relevant runtime dependencies (project ->
// constraint) and the list of provided paths for a project's package.yml.
func FetchMeta(project string) (deps map[string]string, provides []string, err error) {
	body, err := fetchRecipe(project)
	if err != nil {
		return nil, nil, err
	}
	var y pkgYML
	if err := yaml.Unmarshal(body, &y); err != nil {
		return nil, nil, fmt.Errorf("%s/package.yml: %w", project, err)
	}
	deps = map[string]string{}
	osn, arch := HostSlug()
	for k, node := range y.Dependencies {
		if isPlatformKey(k) {
			if platformMatches(k, osn, arch) {
				var sub map[string]string
				_ = node.Decode(&sub)
				for pk, pv := range sub {
					deps[pk] = pv
				}
			}
			continue
		}
		var s string
		_ = node.Decode(&s)
		deps[k] = s
	}
	provides = decodeProvides(y.Provides)
	return deps, provides, nil
}

func isPlatformKey(k string) bool {
	return k == "linux" || k == "darwin" || strings.HasPrefix(k, "linux/") || strings.HasPrefix(k, "darwin/")
}

func platformMatches(k, osn, arch string) bool {
	if k == osn {
		return true
	}
	return k == osn+"/"+arch
}

func decodeProvides(n yaml.Node) []string {
	var list []string
	if err := n.Decode(&list); err == nil {
		return list
	}
	// may be a platform map: {linux: [...], darwin: [...]}
	var m map[string][]string
	if err := n.Decode(&m); err == nil {
		osn, _ := HostSlug()
		return m[osn]
	}
	return nil
}

// --- resolution -------------------------------------------------------------

// Resolved is a project pinned to a concrete version.
type Resolved struct {
	Project string
	Version Ver
}

// ResolveClosure walks the runtime dependency graph breadth-first.
func ResolveClosure(roots map[string]string) ([]Resolved, error) {
	seen := map[string]Ver{}
	queue := []struct{ p, c string }{}
	for p, c := range roots {
		queue = append(queue, struct{ p, c string }{p, c})
	}
	var order []string
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		if _, ok := seen[item.p]; ok {
			continue
		}
		v, err := PickVersion(item.p, item.c)
		if err != nil {
			return nil, err
		}
		seen[item.p] = v
		order = append(order, item.p)
		deps, _, err := FetchMeta(item.p)
		if err != nil {
			return nil, err
		}
		for dp, dc := range deps {
			if _, ok := seen[dp]; !ok {
				queue = append(queue, struct{ p, c string }{dp, dc})
			}
		}
	}
	out := make([]Resolved, 0, len(order))
	for _, p := range order {
		out = append(out, Resolved{p, seen[p]})
	}
	return out, nil
}

// --- download + extract -----------------------------------------------------

// Install downloads and extracts one bottle into pkgxDir (skips if the
// versioned prefix already exists), then writes major/minor convenience links.
// Extraction is atomic — the bottle is unpacked into a temp dir and the
// versioned prefix is renamed into place — so concurrent installs sharing one
// PKGX_DIR never observe a half-extracted prefix.
func Install(r Resolved, pkgxDir string) (bool, error) {
	prefix := filepath.Join(pkgxDir, r.Project, "v"+r.Version.Raw)
	if st, err := os.Stat(prefix); err == nil && st.IsDir() {
		return false, nil // already present
	}
	osn, arch := HostSlug()
	// Prefer gzip (stdlib); fall back to xz for bottles published xz-only.
	body, isXz, err := fetchBottle(r, osn, arch)
	if err != nil {
		return false, err
	}
	defer body.Close()
	var dec io.Reader = body
	if isXz {
		xr, err := xz.NewReader(body)
		if err != nil {
			return false, err
		}
		dec = xr
	} else {
		gz, err := gzip.NewReader(body)
		if err != nil {
			return false, err
		}
		defer gz.Close()
		dec = gz
	}
	// Unpack into a private temp dir, then atomically rename the extracted
	// <project>/v<ver> into place.
	if err := os.MkdirAll(pkgxDir, 0o755); err != nil {
		return false, err
	}
	tmp, err := os.MkdirTemp(pkgxDir, ".tmp-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(tmp)
	if err := untar(dec, tmp); err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(prefix), 0o755); err != nil {
		return false, err
	}
	if err := os.Rename(filepath.Join(tmp, r.Project, "v"+r.Version.Raw), prefix); err != nil {
		// Another concurrent worker may have installed it meanwhile.
		if st, e := os.Stat(prefix); e == nil && st.IsDir() {
			return false, nil
		}
		return false, err
	}
	writeVersionLinks(pkgxDir, r)
	return true, nil
}

// fetchBottle returns the compressed bottle stream, trying .tar.gz then .tar.xz.
// When DistBase selects the OCI transport it pulls the bottle blob and wraps the
// bytes in a reader, so Install (and thus pkgm/pkgx) works over OCI unchanged.
func fetchBottle(r Resolved, osn, arch string) (io.ReadCloser, bool, error) {
	if IsOCI(DistBase) {
		c, err := ociClientForDist()
		if err != nil {
			return nil, false, err
		}
		// The registry tag, which is the flavored one for a glibc-pinned build;
		// the installed prefix stays v<version> either way.
		data, ext, err := c.Pull(r.Project, r.Version.tag(), osn, arch)
		if err != nil {
			return nil, false, err
		}
		return io.NopCloser(bytes.NewReader(data)), ext == ExtTarXz, nil
	}
	base := fmt.Sprintf("%s/%s/%s/%s/v%s", DistBase, r.Project, osn, arch, r.Version.Raw)
	for _, ext := range []struct {
		suffix string
		xz     bool
	}{{ExtTarGz, false}, {ExtTarXz, true}} {
		resp, err := HTTPClient.Get(base + ext.suffix)
		if err != nil {
			return nil, false, err
		}
		if resp.StatusCode == 200 {
			return resp.Body, ext.xz, nil
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			return nil, false, fmt.Errorf("GET %s: %s", base+ext.suffix, resp.Status)
		}
	}
	return nil, false, fmt.Errorf("no bottle for %s v%s (%s/%s)", r.Project, r.Version.Raw, osn, arch)
}

func untar(r io.Reader, dest string) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dest, hdr.Name)
		if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("unsafe path in tar: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeSymlink:
			_ = os.MkdirAll(filepath.Dir(target), 0o755)
			_ = os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return err
			}
		case tar.TypeLink:
			_ = os.MkdirAll(filepath.Dir(target), 0o755)
			_ = os.Remove(target)
			if err := os.Link(filepath.Join(dest, hdr.Linkname), target); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode)&0o777)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		}
	}
}

// writeVersionLinks creates v{maj}, v{maj}.{min} and v* -> v{full} symlinks
// alongside the extracted prefix, matching pkgx's convenience aliases.
func writeVersionLinks(pkgxDir string, r Resolved) {
	dir := filepath.Join(pkgxDir, r.Project)
	full := "v" + r.Version.Raw
	n := r.Version.Nums
	aliases := []string{"v*"}
	if len(n) >= 1 {
		aliases = append(aliases, "v"+strconv.Itoa(n[0]))
	}
	if len(n) >= 2 {
		aliases = append(aliases, "v"+strconv.Itoa(n[0])+"."+strconv.Itoa(n[1]))
	}
	for _, a := range aliases {
		if a == full {
			continue
		}
		p := filepath.Join(dir, a)
		_ = os.Remove(p)
		_ = os.Symlink(full, p)
	}
}
