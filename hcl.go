package bottle

import (
	"fmt"
	"math/big"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"gopkg.in/yaml.v3"
)

// HCLToYAML turns a package.hcl into the package.yml bytes the rest of this
// package already knows how to read.
//
// It lives here, and not in bk where the HCL front-end was written, because
// the CLIENT has to read these files: the pantry overlay is fetched at install
// time, and a recipe written in HCL is unreadable to a pkgx that cannot parse
// it. bk imports bottle, so the parser cannot live in bk without a cycle — and
// two copies of it would drift.
//
// Converting to YAML rather than decoding straight into a recipe keeps ONE
// parse path: whatever validation and quirk-handling the YAML side has is
// applied to both formats, and a recipe written either way cannot behave
// differently.
//
// Cost, measured before it was added: pkgx goes from 8.81 MB to 9.45 MB.
func HCLToYAML(src []byte, filename string) ([]byte, error) {
	doc, err := HCLToMap(src, filename)
	if err != nil {
		return nil, err
	}
	return yaml.Marshal(doc)
}

// HCLToMap parses package.hcl into the generic document shape a package.yml
// decodes to.
func HCLToMap(src []byte, filename string) (map[string]any, error) {
	f, diags := hclsyntax.ParseConfig(src, filename, hcl.InitialPos)
	if diags.HasErrors() {
		return nil, fmt.Errorf("hcl: parse: %s", diags.Error())
	}
	return hclBodyToMap(f.Body.(*hclsyntax.Body))
}

// hclBodyToMap converts a body's attributes and nested blocks into a map.
func hclBodyToMap(body *hclsyntax.Body) (map[string]any, error) {
	out := make(map[string]any, len(body.Attributes)+len(body.Blocks))
	for name, attr := range body.Attributes {
		v, diags := attr.Expr.Value(nil)
		if diags.HasErrors() {
			return nil, fmt.Errorf("hcl: %s: %s", name, diags.Error())
		}
		g, err := hclCtyToGo(v)
		if err != nil {
			// Not reachable from HCL text: with no evaluation context every
			// value an attribute can hold is one hclCtyToGo renders, and a
			// reference that is not fails above as a diagnostic instead. It
			// stays because the two functions can drift — a future cty type
			// would arrive here first — and because the alternative was a test
			// that exercised a COPY of these three lines, which would have
			// agreed with itself whatever they said.
			return nil, fmt.Errorf("hcl: %s: %w", name, err)
		}
		out[name] = g
	}
	for _, block := range body.Blocks {
		if _, exists := out[block.Type]; exists {
			// A block and an attribute of the same name are two answers to one
			// question, and picking either silently would build something the
			// file does not say.
			return nil, fmt.Errorf("hcl: duplicate key %q (block and/or attribute)", block.Type)
		}
		m, err := hclBodyToMap(block.Body)
		if err != nil {
			return nil, err
		}
		out[block.Type] = m
	}
	return out, nil
}

// hclCtyToGo converts a cty.Value into the plain Go value a YAML decode would
// yield: string, float64, bool, nil, []any, map[string]any.
func hclCtyToGo(v cty.Value) (any, error) {
	if v.IsNull() {
		return nil, nil
	}
	t := v.Type()
	switch {
	case t == cty.String:
		return v.AsString(), nil
	case t == cty.Bool:
		return v.True(), nil
	case t == cty.Number:
		// An integral number comes back as an int, not a float.
		//
		// cty has one number type, so the choice is ours — and float64 was the
		// wrong one. yaml.Marshal writes float64(20250127) as 2.0250127e+07,
		// which decodes as a float, and a recipe asking for abseil.io at
		// version 20250127 would have been handed 2.0250127e+07 at INSTALL
		// time. Found by converting the whole upstream pantry and comparing
		// each recipe against itself; dozzle.dev is the one that has it.
		//
		// A whole number that was written 11.0 still arrives as 11, because
		// HCL cannot tell the two apart. That is a limit of the format, and
		// the four recipes it affects keep their YAML.
		bf := v.AsBigFloat()
		if bf.IsInt() {
			if i, acc := bf.Int64(); acc == big.Exact {
				return i, nil
			}
		}
		f, _ := bf.Float64()
		return f, nil
	case t.IsTupleType(), t.IsListType(), t.IsSetType():
		var out []any
		for _, e := range v.AsValueSlice() {
			g, err := hclCtyToGo(e)
			if err != nil {
				return nil, err
			}
			out = append(out, g)
		}
		return out, nil
	case t.IsObjectType(), t.IsMapType():
		out := make(map[string]any)
		for k, e := range v.AsValueMap() {
			g, err := hclCtyToGo(e)
			if err != nil {
				return nil, err
			}
			out[k] = g
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported HCL value type %s", t.FriendlyName())
	}
}
