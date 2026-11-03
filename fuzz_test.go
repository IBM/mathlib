/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package math

import (
	"bytes"
	"fmt"
	"testing"
)

// FuzzUnmarshalJSONCurveID targets the C1 fix: an out-of-range or negative
// "curve" field in the JSON payload must be rejected with an error, never
// cause an index-out-of-range panic when indexing Curves.
func FuzzUnmarshalJSONCurveID(f *testing.F) {
	f.Add(0, []byte("AAAA"))
	f.Add(-1, []byte("AAAA"))
	f.Add(len(Curves), []byte("AAAA"))
	f.Add(len(Curves)+1000, []byte("AAAA"))
	f.Add(1<<31-1, []byte(""))
	f.Add(-1<<31, []byte("!!!!"))

	f.Fuzz(func(t *testing.T, curveID int, element []byte) {
		payload := fmt.Appendf(nil, `{"curve": %d, "element": %q}`, curveID, element)

		zr := &Zr{}
		_ = zr.UnmarshalJSON(payload)

		g1 := &G1{}
		_ = g1.UnmarshalJSON(payload)

		g2 := &G2{}
		_ = g2.UnmarshalJSON(payload)

		gt := &Gt{}
		_ = gt.UnmarshalJSON(payload)
	})
}

// FuzzHashToGWithDomain targets the C2 fix: HashToG1WithDomain/HashToG2WithDomain
// must never panic regardless of domain length or content, returning nil instead
// when the underlying driver rejects the input.
func FuzzHashToGWithDomain(f *testing.F) {
	f.Add(0, []byte("hello world"), make([]byte, 256))
	f.Add(0, []byte(""), []byte(""))
	f.Add(int(BLS12_381), []byte("data"), make([]byte, 255))
	f.Add(int(BLS12_381), []byte("data"), make([]byte, 256))
	f.Add(int(FP256BN_AMCL), []byte("data"), make([]byte, 300))

	f.Fuzz(func(t *testing.T, curveIdx int, data, domain []byte) {
		n := len(Curves)
		idx := curveIdx % n
		if idx < 0 {
			idx += n
		}
		curve := Curves[idx]

		_ = curve.HashToG1WithDomain(data, domain)
		_ = curve.HashToG2WithDomain(data, domain)
	})
}

// FuzzDecodeCanonical checks that every accepted encoding is canonical: a
// successful decode must re-encode to exactly the input.
func FuzzDecodeCanonical(f *testing.F) {
	for i, c := range Curves {
		f.Add(i, 0, c.GenG1.Bytes())
		f.Add(i, 1, c.GenG1.Compressed())
		f.Add(i, 2, c.GenG2.Bytes())
		f.Add(i, 3, c.GenG2.Compressed())
		f.Add(i, 4, c.GenGt.Bytes())
		f.Add(i, 5, c.GroupOrder.Bytes())
		f.Add(i, 0, c.NewG1().Bytes())
	}

	f.Fuzz(func(t *testing.T, curveIdx, kind int, b []byte) {
		n := len(Curves)
		c := Curves[((curveIdx%n)+n)%n]

		var out []byte
		switch ((kind % 6) + 6) % 6 {
		case 0:
			if p, err := c.NewG1FromBytes(b); err == nil {
				out = p.Bytes()
			}
		case 1:
			if p, err := c.NewG1FromCompressed(b); err == nil {
				out = p.Compressed()
			}
		case 2:
			if p, err := c.NewG2FromBytes(b); err == nil {
				out = p.Bytes()
			}
		case 3:
			if p, err := c.NewG2FromCompressed(b); err == nil {
				out = p.Compressed()
			}
		case 4:
			if g, err := c.NewGtFromBytes(b); err == nil {
				out = g.Bytes()
			}
		case 5:
			if z, err := c.NewZrFromBytesCanonical(b); err == nil {
				out = z.Bytes()
			}
		}
		if out != nil && !bytes.Equal(out, b) {
			t.Fatalf("non-canonical encoding accepted: %x re-encodes to %x", b, out)
		}
	})
}
