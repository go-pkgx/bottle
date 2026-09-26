package bottle

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

// TestHCLToYAMLMatchesTheYAMLItReplaces: the two formats must reach the same
// document, or a recipe would behave differently for having been rewritten.
func TestHCLToYAMLMatchesTheYAMLItReplaces(t *testing.T) {
	got, err := HCLToYAML([]byte(`
dependencies = { "openssl.org" = "^3" }
provides     = ["bin/x"]

build {
  script = <<EOT
make PREFIX=$${DEST} install
EOT
}
`), "x.hcl")
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	for _, want := range []string{"openssl.org: ^3", "bin/x", "make PREFIX=${DEST} install"} {
		if !strings.Contains(s, want) {
			t.Errorf("want %q in the yaml:\n%s", want, s)
		}
	}
	// The doubled sigil is HCL's way of spelling a literal one, and it must be
	// gone by the time the script reaches a shell.
	if strings.Contains(s, "$${") {
		t.Errorf("the escape must not survive into the yaml:\n%s", s)
	}
}

// Every value shape a recipe can hold, through the converter.
func TestHCLToMapValueShapes(t *testing.T) {
	m, err := HCLToMap([]byte(`
s = "text"
b = true
n = 3
f = 1.5
nul = null
list = ["a", 1]
obj = { "a.b" = "v" }

blk {
  inner = "x"
}
`), "x.hcl")
	if err != nil {
		t.Fatal(err)
	}
	// n is an int64 and f a float64: an integral number keeps its integerness,
	// because yaml.Marshal renders a large float64 in exponent form and a
	// version pinned to 20250127 must not become 2.0250127e+07.
	if m["s"] != "text" || m["b"] != true || m["n"] != int64(3) || m["f"] != 1.5 || m["nul"] != nil {
		t.Errorf("scalars: %#v", m)
	}
	if l, ok := m["list"].([]any); !ok || len(l) != 2 {
		t.Errorf("list: %#v", m["list"])
	}
	if o, ok := m["obj"].(map[string]any); !ok || o["a.b"] != "v" {
		t.Errorf("object: %#v", m["obj"])
	}
	if blk, ok := m["blk"].(map[string]any); !ok || blk["inner"] != "x" {
		t.Errorf("block: %#v", m["blk"])
	}
}

// A block and an attribute of the same name are two answers to one question.
// Picking either silently would build something the file does not say.
func TestHCLDuplicateKeyRefused(t *testing.T) {
	_, err := HCLToMap([]byte("build = \"x\"\nbuild {\n  y = 1\n}\n"), "x.hcl")
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("want a duplicate-key refusal, got %v", err)
	}
}

func TestHCLErrors(t *testing.T) {
	if _, err := HCLToMap([]byte("build { script = "), "x.hcl"); err == nil {
		t.Error("a syntax error must be reported")
	}
	if _, err := HCLToMap([]byte("x = undefined_ref\n"), "x.hcl"); err == nil {
		t.Error("an unresolvable reference must be reported")
	}
	if _, err := HCLToYAML([]byte("x = {"), "x.hcl"); err == nil {
		t.Error("HCLToYAML must surface a parse failure")
	}
}

// A cty value with no Go equivalent must be REFUSED rather than guessed at:
// putting something in a recipe the file never said is worse than failing.
//
// Reached directly. A `for` expression looked like a candidate and is not —
// it evaluates to an ordinary tuple — so the arm is not reachable from HCL
// text with no evaluation context, which is exactly why it needs a test of
// its own rather than a plausible-looking input.
func TestHCLUnsupportedValue(t *testing.T) {
	capsule := cty.Capsule("thing", reflect.TypeOf(struct{}{}))
	bad := cty.CapsuleVal(capsule, &struct{}{})
	if _, err := hclCtyToGo(bad); err == nil {
		t.Error("an unconvertible value must be refused")
	}
	// And from inside a container. An element the converter cannot render is
	// not a container it can render with a hole in it, so the failure has to
	// travel outward rather than be dropped where it was found.
	if _, err := hclCtyToGo(cty.TupleVal([]cty.Value{bad})); err == nil {
		t.Error("an unconvertible list element must be refused")
	}
	if _, err := hclCtyToGo(cty.ObjectVal(map[string]cty.Value{"k": bad})); err == nil {
		t.Error("an unconvertible object value must be refused")
	}
}

// TestFetchRecipePrefersHCL.
//
// Our own overlay is written in HCL; upstream's pantry is YAML. Asking only
// for the yaml is how an override silently stops applying: the overlay 404s,
// resolution falls through to upstream, and the recipe that builds is the one
// the overlay exists to replace. Nothing fails — the wrong thing is built.
func TestFetchRecipePrefersHCL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/overlay/a.org/package.hcl":
			fmt.Fprint(w, "dependencies = { \"openssl.org\" = \"^3\" }\n")
		case "/pantry/a.org/package.yml":
			fmt.Fprint(w, "dependencies:\n  openssl.org: ^1.1\n")
		case "/pantry/b.org/package.yml":
			fmt.Fprint(w, "dependencies:\n  zlib.net: 1\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	o, p := PantryOverlay, PantryBase
	defer func() { PantryOverlay, PantryBase = o, p }()
	PantryOverlay, PantryBase = srv.URL+"/overlay", srv.URL+"/pantry"

	// The overlay's HCL wins over the pantry's YAML for the same project.
	body, err := fetchRecipe("a.org")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "^3") {
		t.Errorf("the overlay's hcl must win:\n%s", body)
	}
	// A project the overlay does not carry falls through to the pantry.
	body, err = fetchRecipe("b.org")
	if err != nil || !strings.Contains(string(body), "zlib.net") {
		t.Errorf("fall through to the pantry: %s, %v", body, err)
	}
	// Neither has it: an error naming both places, rather than an empty recipe.
	if _, err := fetchRecipe("nowhere.org"); err == nil {
		t.Error("a project in neither tree must be an error")
	}
}

// An error inside a nested structure must carry outward rather than being
// swallowed at the level that found it — a recipe half-read is not a recipe.
func TestHCLNestedErrorsSurface(t *testing.T) {
	for name, src := range map[string]string{
		"inside a block":   "blk {\n  x = undefined_ref\n}\n",
		"inside a list":    "x = [undefined_ref]\n",
		"inside an object": "x = { k = undefined_ref }\n",
	} {
		if _, err := HCLToMap([]byte(src), "x.hcl"); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// A large integer must stay an integer. cty has one number type, so the choice
// of Go type is ours, and float64 was the wrong one: yaml.Marshal writes
// float64(20250127) as 2.0250127e+07, so a recipe pinning abseil.io to
// 20250127 would have been handed 2.0250127e+07 at INSTALL time — a client
// bug, not a conversion one. Found by converting all 1907 upstream recipes and
// comparing each against itself.
func TestHCLIntegersDoNotBecomeFloats(t *testing.T) {
	y, err := HCLToYAML([]byte("build { dependencies = { \"abseil.io\" = 20250127 } }\n"), "x.hcl")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(y), "20250127") || strings.Contains(string(y), "e+07") {
		t.Errorf("a large integer must survive:\n%s", y)
	}
	// And a genuine fraction stays one.
	y, err = HCLToYAML([]byte("x = 1.5\n"), "x.hcl")
	if err != nil || !strings.Contains(string(y), "1.5") {
		t.Errorf("a fraction must survive: %s, %v", y, err)
	}
	// A number too large for an int64 falls back to a float rather than
	// silently truncating.
	m, err := HCLToMap([]byte("x = 99999999999999999999999\n"), "x.hcl")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m["x"].(float64); !ok {
		t.Errorf("an out-of-range integer must fall back to float, got %T", m["x"])
	}
}
