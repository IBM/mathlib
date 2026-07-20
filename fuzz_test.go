/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package math

import (
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
