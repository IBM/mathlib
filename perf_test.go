/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package math

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func newRandZr(rng io.Reader, m *big.Int) *big.Int {
	bi, err := rand.Int(rng, m)
	if err != nil {
		panic(err)
	}

	return bi
}

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

func pokPedersenCommittmentInitGurvy(b *testing.B) (io.Reader, *bls12381.G1Affine, *bls12381.G1Affine, *big.Int) {
	rng := rand.Reader

	_, _, g1, _ := bls12381.Generators()

	g := g1.ScalarMultiplication(&g1, newRandZr(rng, fr.Modulus()))
	h := g1.ScalarMultiplication(&g1, newRandZr(rng, fr.Modulus()))
	x := newRandZr(rng, fr.Modulus())

	return rng, g, h, x
}

func Benchmark_PedersenCommitmentPoKGurvy(b *testing.B) {
	rng, g, h, x := pokPedersenCommittmentInitGurvy(b)

	b.ResetTimer()

	b.Run("bls12-381", func(b *testing.B) {

		for i := 0; i < b.N; i++ {

			r := newRandZr(rng, fr.Modulus())
			c := g.ScalarMultiplication(g, x)
			c.Add(c, h.ScalarMultiplication(h, r))

			x_tilde := newRandZr(rng, fr.Modulus())
			r_tilde := newRandZr(rng, fr.Modulus())
			t := g.ScalarMultiplication(g, x_tilde)
			t.Add(c, h.ScalarMultiplication(h, r_tilde))

			chal := newRandZr(rng, fr.Modulus())

			x_hat := new(big.Int).Add(x_tilde, new(big.Int).Mul(chal, x))
			r_hat := new(big.Int).Add(r_tilde, new(big.Int).Mul(chal, r))

			v1 := g.ScalarMultiplication(g, x_hat)
			v1.Add(v1, h.ScalarMultiplication(h, r_hat))

			v2 := c.ScalarMultiplication(c, chal)
			v2.Add(v2, t)

			if !v1.Equal(v2) {
				panic("invalid PoK")
			}
		}
	})
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
