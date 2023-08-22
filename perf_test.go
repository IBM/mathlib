/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package math

import (
	"fmt"
	"io"
	"testing"
)

func pokPedersenCommittmentInit(b *testing.B, curve *Curve) (io.Reader, *G1, *G1, *Zr, error) {
	rng, err := curve.Rand()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	g := curve.GenG1.Mul(curve.NewRandomZr(rng))
	h := curve.GenG1.Mul(curve.NewRandomZr(rng))
	x := curve.NewRandomZr(rng)

	return rng, g, h, x, nil
}

func Benchmark_PedersenCommitmentPoK(b *testing.B) {

	for _, curve := range Curves {
		rng, g, h, x, err := pokPedersenCommittmentInit(b, curve)
		if err != nil {
			panic(err)
		}

		b.ResetTimer()

		b.Run(fmt.Sprintf("PoK Pedersen Commitment with curve %s", CurveIDToString(curve.curveID)), func(b *testing.B) {

			for i := 0; i < b.N; i++ {
				r := curve.NewRandomZr(rng)
				c := g.Mul(x)
				c.Add(h.Mul(r))

				x_tilde := curve.NewRandomZr(rng)
				r_tilde := curve.NewRandomZr(rng)
				t := g.Mul(x_tilde)
				t.Add(h.Mul(r_tilde))

				chal := curve.NewRandomZr(rng)

				x_hat := x_tilde.Plus(chal.Mul(x))
				r_hat := r_tilde.Plus(chal.Mul(r))

				v1 := g.Mul(x_hat)
				v1.Add(h.Mul(r_hat))

				v2 := c.Mul(chal)
				v2.Add(t)

				if !v1.Equals(v2) {
					panic("invalid PoK")
				}
			}
		})
	}
}
