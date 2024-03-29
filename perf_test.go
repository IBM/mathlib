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

func blsInit(b *testing.B, curve *Curve) (*G2, *Zr, error) {
	rng, err := curve.Rand()
	if err != nil {
		return nil, nil, err
	}

	g := curve.GenG2.Mul(curve.NewRandomZr(rng))
	x := curve.NewRandomZr(rng)

	return g, x, nil
}

func blsInitGurvy(b *testing.B) (*bls12381.G2Affine, *big.Int) {
	rng := rand.Reader

	_, _, _, g2 := bls12381.Generators()

	g := g2.ScalarMultiplication(&g2, newRandZr(rng, fr.Modulus()))
	x := newRandZr(rng, fr.Modulus())

	return g, x
}

func blsInitKilic(b *testing.B) (*kilic.PointG2, *big.Int) {
	rng := rand.Reader

	_g := kilic.NewG2()
	g2 := _g.One()
	g := _g.New()

	_g.MulScalarBig(g, g2, newRandZr(rng, fr.Modulus()))
	x := newRandZr(rng, fr.Modulus())

	return g, x
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

func Benchmark_Sequential_PedersenCommitmentPoKKilic(b *testing.B) {
	rng, g, h, x := pokPedersenCommittmentInitKilic(b)
	_g := kilic.NewG1()
	tmp := _g.New()
	mod := fr.Modulus()

	b.ResetTimer()

	b.Run("curve BLS12_381 (direct)", func(b *testing.B) {

		for i := 0; i < b.N; i++ {
			r := newRandZr(rng, mod)
			c := _g.New()
			_g.MulScalarBig(c, g, x)
			_g.MulScalarBig(tmp, h, r)
			_g.Add(c, c, tmp)

			x_tilde := newRandZr(rng, mod)
			r_tilde := newRandZr(rng, mod)
			t := _g.New()
			_g.MulScalarBig(t, g, x_tilde)
			_g.MulScalarBig(tmp, h, r_tilde)
			_g.Add(t, t, tmp)

			chal := newRandZr(rng, mod)

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

func Benchmark_Sequential_PedersenCommitmentPoKGurvy(b *testing.B) {
	rng, g, h, x := pokPedersenCommittmentInitGurvy(b)

	b.ResetTimer()

	b.Run("curve BLS12_381_GURVY (direct)", func(b *testing.B) {

		for i := 0; i < b.N; i++ {

			r := newRandZr(rng, fr.Modulus())
			c := new(bls12381.G1Affine).ScalarMultiplication(g, x)
			c.Add(c, new(bls12381.G1Affine).ScalarMultiplication(h, r))

			x_tilde := newRandZr(rng, fr.Modulus())
			r_tilde := newRandZr(rng, fr.Modulus())
			t := new(bls12381.G1Affine).ScalarMultiplication(g, x_tilde)
			t.Add(t, new(bls12381.G1Affine).ScalarMultiplication(h, r_tilde))

			chal := newRandZr(rng, fr.Modulus())

			x_hat := new(big.Int).Add(x_tilde, new(big.Int).Mul(chal, x))
			r_hat := new(big.Int).Add(r_tilde, new(big.Int).Mul(chal, r))

			v1 := new(bls12381.G1Affine).ScalarMultiplication(g, x_hat)
			v1.Add(v1, new(bls12381.G1Affine).ScalarMultiplication(h, r_hat))

			v2 := new(bls12381.G1Affine).ScalarMultiplication(c, chal)
			v2.Add(v2, t)

			if !v1.Equal(v2) {
				panic("invalid PoK")
			}
		}
	})
}

func Benchmark_Sequential_PedersenCommitmentPoK(b *testing.B) {

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

func Benchmark_Sequential_BLS(b *testing.B) {

	for _, curve := range Curves {
		g, x, err := blsInit(b, curve)
		if err != nil {
			panic(err)
		}

		pk := g.Mul(x)

		b.ResetTimer()

		var sig *G1

		b.Run(fmt.Sprintf("sign curve %s", CurveIDToString(curve.curveID)), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				h := curve.HashToG1WithDomain([]byte("msg"), []byte("context"))
				sig = h.Mul(x)
			}
		})

		sig.Neg()

		b.Run(fmt.Sprintf("verify curve %s", CurveIDToString(curve.curveID)), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				h := curve.HashToG1WithDomain([]byte("msg"), []byte("context"))

				p := curve.Pairing2(g, sig, pk, h)

				p = curve.FExp(p)
				if !p.IsUnity() {
					panic("invalid signature")
				}
			}
		})
	}
}

func Benchmark_Parallel_BLSGurvy(b *testing.B) {
	g, x := blsInitGurvy(b)
	pk := new(bls12381.G2Affine).ScalarMultiplication(g, x)

	b.ResetTimer()

	var sig *bls12381.G1Affine

	b.Run("sign curve BLS12_381_GURVY (direct)", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				h, err := bls12381.HashToG1([]byte("msg"), []byte("context"))
				if err != nil {
					panic(err)
				}
				sig = new(bls12381.G1Affine).ScalarMultiplication(&h, x)
			}
		})
	})

	sig.Neg(sig)

	b.ResetTimer()

	b.Run("verify curve BLS12_381_GURVY (direct)", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				h, err := bls12381.HashToG1([]byte("msg"), []byte("context"))
				if err != nil {
					panic(err)
				}

				t, err := bls12381.MillerLoop([]bls12381.G1Affine{*sig, h}, []bls12381.G2Affine{*g, *pk})
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
	})
}

func Benchmark_Parallel_BLSKilic(b *testing.B) {
	g, x := blsInitKilic(b)
	_g := kilic.NewG2()
	pk := _g.New()
	_g.MulScalarBig(pk, g, x)

	b.ResetTimer()

	var sig *kilic.PointG1

	b.Run("sign curve BLS12_381_GURVY (direct)", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			_g := kilic.NewG1()
			for pb.Next() {
				g1 := kilic.NewG1()
				h, err := g1.HashToCurve([]byte("msg"), []byte("context"))
				if err != nil {
					panic(err)
				}

				sig = _g.New()
				_g.MulScalarBig(sig, h, x)
			}
		})
	})

	kilic.NewG1().Neg(sig, sig)

	b.ResetTimer()

	b.Run("verify curve BLS12_381_GURVY (direct)", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				g1 := kilic.NewG1()
				h, err := g1.HashToCurve([]byte("msg"), []byte("context"))
				if err != nil {
					panic(err)
				}
				bls := kilic.NewEngine()
				bls.AddPair(sig, g)
				bls.AddPair(h, pk)

				if !bls.Check() {
					panic("invalid signature")
				}
			}
		})
	})
}

func Benchmark_Parallel_BLS(b *testing.B) {
	for _, curve := range Curves {
		if curve.curveID != BLS12_381 && curve.curveID != BLS12_381_GURVY {
			continue
		}

		g, x, err := blsInit(b, curve)
		if err != nil {
			panic(err)
		}

		pk := g.Mul(x)

		b.ResetTimer()

		var sig *G1

		b.Run(fmt.Sprintf("sign curve %s", CurveIDToString(curve.curveID)), func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					h := curve.HashToG1WithDomain([]byte("msg"), []byte("context"))
					sig = h.Mul(x)
				}
			})
		})

		sig.Neg()

		b.Run(fmt.Sprintf("verify curve %s", CurveIDToString(curve.curveID)), func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					h := curve.HashToG1WithDomain([]byte("msg"), []byte("context"))

					p := curve.Pairing2(g, sig, pk, h)

					p = curve.FExp(p)
					if !p.IsUnity() {
						panic("invalid signature")
					}
				}
			})
		})
	}
}

func Benchmark_Parallel_IndividualOpsGurvy(b *testing.B) {
	curve := Curves[BLS12_381_GURVY]
	g_gurv, x_gurv := blsInitGurvy(b)
	g_math, x_math, err := blsInit(b, curve)
	if err != nil {
		panic(err)
	}

	pk_gurv := new(bls12381.G2Affine).ScalarMultiplication(g_gurv, x_gurv)
	pk_math := g_math.Mul(x_math)

	var h_gurv bls12381.G1Affine
	var h_math *G1

	var sig_gurv *bls12381.G1Affine
	var sig_math *G1

	var t_gurv bls12381.GT
	var t_math *Gt

	b.Run("hash/gurvy", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				h_gurv, _ = bls12381.HashToG1([]byte("msg"), []byte("context"))
			}
		})
	})

	b.Run("hash/mathlib", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				h_math = curve.HashToG1WithDomain([]byte("msg"), []byte("context"))
			}
		})
	})

	b.Run("sign/gurvy", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				sig_gurv = new(bls12381.G1Affine).ScalarMultiplication(&h_gurv, x_gurv)
			}
		})
	})

	b.Run("sign/mathlib", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				sig_math = h_math.Mul(x_math)
			}
		})
	})

	b.Run("pairing2/gurvy", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {

				t_gurv, err = bls12381.MillerLoop([]bls12381.G1Affine{*sig_gurv, h_gurv}, []bls12381.G2Affine{*g_gurv, *pk_gurv})
				if err != nil {
					panic(err)
				}

				t_gurv = bls12381.FinalExponentiation(&t_gurv)
			}
		})
	})

	b.Run("pairing2/mathlib", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				t_math = curve.Pairing2(g_math, sig_math, pk_math, h_math)

				t_math = curve.FExp(t_math)
			}
		})
	})
}

func Benchmark_Parallel_IndividualOpsKilic(b *testing.B) {
	curve := Curves[BLS12_381]
	g_kili, x_kili := blsInitKilic(b)
	g_math, x_math, err := blsInit(b, curve)
	if err != nil {
		panic(err)
	}

	_g := kilic.NewG2()
	pk_kili := _g.New()
	_g.MulScalarBig(pk_kili, g_kili, x_kili)
	pk_math := g_math.Mul(x_math)

	var h_kili *kilic.PointG1
	var h_math *G1

	var sig_kili *kilic.PointG1
	var sig_math *G1

	var t_math *Gt

	b.Run("hash/kilic", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				g1 := kilic.NewG1()
				h_kili, _ = g1.HashToCurve([]byte("msg"), []byte("context"))
			}
		})
	})

	b.Run("hash/mathlib", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				h_math = curve.HashToG1WithDomain([]byte("msg"), []byte("context"))
			}
		})
	})

	b.Run("sign/kilic", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			_g := kilic.NewG1()
			for pb.Next() {
				sig_kili = _g.New()
				_g.MulScalarBig(sig_kili, h_kili, x_kili)
			}
		})
	})

	b.Run("sign/mathlib", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				sig_math = h_math.Mul(x_math)
			}
		})
	})

	b.Run("pairing2/kilic", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				bls := kilic.NewEngine()
				bls.AddPair(sig_kili, g_kili)
				bls.AddPair(h_kili, pk_kili)
				bls.Result()
			}
		})
	})

	b.Run("pairing2/mathlib", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				t_math = curve.Pairing2(g_math, sig_math, pk_math, h_math)

				t_math = curve.FExp(t_math)
			}
		})
	})
}
