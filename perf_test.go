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
	kilic "github.com/kilic/bls12-381"
)

func newRandZr(rng io.Reader, m *big.Int) *big.Int {
	bi, err := rand.Int(rng, m)
	if err != nil {
		panic(err)
	}

	return bi
}

func blsInit(b *testing.B, curve *Curve) (*G1, *G2, *Zr, error) {
	rng, err := curve.Rand()
	if err != nil {
		return nil, nil, nil, err
	}

	g := curve.GenG2.Mul(curve.NewRandomZr(rng))
	g = curve.GenG2.Mul(curve.NewZrFromInt(35))
	h := curve.GenG1.Mul(curve.NewRandomZr(rng))
	h = curve.GenG1.Mul(curve.NewZrFromInt(135))
	x := curve.NewRandomZr(rng)
	x = curve.NewZrFromInt(20)

	return h, g, x, nil
}

func blsInitGurvy(b *testing.B) (*bls12381.G1Affine, *bls12381.G2Affine, *big.Int) {
	rng := rand.Reader

	_, _, g1, g2 := bls12381.Generators()

	// g := g2.ScalarMultiplication(&g2, newRandZr(rng, fr.Modulus()))
	g := g2.ScalarMultiplication(&g2, big.NewInt(35))
	// h := g1.ScalarMultiplication(&g1, newRandZr(rng, fr.Modulus()))
	h := g1.ScalarMultiplication(&g1, big.NewInt(135))
	x := newRandZr(rng, fr.Modulus())
	x = big.NewInt(20)

	return h, g, x
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

func pokPedersenCommittmentInitKilic(b *testing.B) (io.Reader, *kilic.PointG1, *kilic.PointG1, *big.Int) {
	rng := rand.Reader

	_g := kilic.NewG1()
	g1 := _g.One()
	g := _g.New()
	h := _g.New()

	_g.MulScalarBig(g, g1, newRandZr(rng, fr.Modulus()))
	_g.MulScalarBig(h, g1, newRandZr(rng, fr.Modulus()))
	x := newRandZr(rng, fr.Modulus())

	return rng, g, h, x
}

func Benchmark_PedersenCommitmentPoKKilic(b *testing.B) {
	rng, g, h, x := pokPedersenCommittmentInitKilic(b)
	_g := kilic.NewG1()
	tmp := _g.New()

	b.ResetTimer()

	b.Run("curve BLS12_381 (direct)", func(b *testing.B) {

		for i := 0; i < b.N; i++ {
			r := newRandZr(rng, fr.Modulus())
			c := _g.New()
			_g.MulScalarBig(c, g, x)
			_g.MulScalarBig(tmp, h, r)
			_g.Add(c, c, tmp)

			x_tilde := newRandZr(rng, fr.Modulus())
			r_tilde := newRandZr(rng, fr.Modulus())
			t := _g.New()
			_g.MulScalarBig(t, g, x_tilde)
			_g.MulScalarBig(tmp, h, r_tilde)
			_g.Add(t, t, tmp)

			chal := newRandZr(rng, fr.Modulus())

			x_hat := new(big.Int).Add(x_tilde, new(big.Int).Mul(chal, x))
			r_hat := new(big.Int).Add(r_tilde, new(big.Int).Mul(chal, r))

			v1 := _g.New()
			_g.MulScalarBig(v1, g, x_hat)
			_g.MulScalarBig(tmp, h, r_hat)
			_g.Add(v1, v1, tmp)

			v2 := _g.New()
			_g.MulScalarBig(v2, c, chal)
			_g.Add(v2, v2, t)

			if !_g.Equal(v1, v2) {
				panic("invalid PoK")
			}
		}
	})
}

func Benchmark_PedersenCommitmentPoKGurvy(b *testing.B) {
	rng, g, h, x := pokPedersenCommittmentInitGurvy(b)

	b.ResetTimer()

	b.Run("curve BLS12_381_GURVY (direct)", func(b *testing.B) {

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

		b.Run(fmt.Sprintf("curve %s", CurveIDToString(curve.curveID)), func(b *testing.B) {

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

func Benchmark_BLSGurvy(b *testing.B) {
	h, g, x := blsInitGurvy(b)

	b.ResetTimer()

	b.Run("curve BLS12_381_GURVY (direct)", func(b *testing.B) {

		for i := 0; i < b.N; i++ {
			pk := new(bls12381.G2Affine).ScalarMultiplication(g, x)
			sig := new(bls12381.G1Affine).ScalarMultiplication(h, x)

			sig.Neg(sig)

			t, err := bls12381.MillerLoop([]bls12381.G1Affine{*sig, *h}, []bls12381.G2Affine{*g, *pk})
			if err != nil {
				panic(err)
			}

			t1 := bls12381.FinalExponentiation(&t)

			unity := &bls12381.GT{}
			unity.SetOne()
			if !unity.Equal(&t1) {
				panic("invalid signature")
			}
		}
	})
}

func Benchmark_BLS(b *testing.B) {

	for _, curve := range Curves {
		h, g, x, err := blsInit(b, curve)
		if err != nil {
			panic(err)
		}

		b.ResetTimer()

		b.Run(fmt.Sprintf("curve %s", CurveIDToString(curve.curveID)), func(b *testing.B) {

			for i := 0; i < b.N; i++ {
				pk := g.Mul(x)
				sig := h.Mul(x)

				sig.Neg()

				p := curve.Pairing2(g, sig, pk, h)

				p = curve.FExp(p)
				if !p.IsUnity() {
					panic("invalid signature")
				}
			}
		})
	}
}
