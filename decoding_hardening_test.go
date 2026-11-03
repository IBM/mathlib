/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package math

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// Regression tests for decoding/robustness issues: points that decoded
// silently to infinity, missing subgroup checks, length/format confusion,
// non-modular Zr comparisons and related Zr/Gt corner cases.

func enc32(x *big.Int) []byte {
	return x.FillBytes(make([]byte, 32))
}

func orderOf(c *Curve) *big.Int {
	return new(big.Int).Set(c.GroupOrder.BigInt())
}

// Off-curve G1 encodings must be rejected, not decoded to infinity.
func TestG1OffCurveRejected(t *testing.T) {
	for _, c := range Curves {
		t.Run(CurveIDToString(c.ID()), func(t *testing.T) {
			b := c.GenG1.Bytes()
			b[len(b)-1] ^= 0x01 // (x, y') is no longer on the curve

			_, err := c.NewG1FromBytes(b)
			require.Error(t, err)
		})
	}
}

// G1 encodings with an invalid SEC1 prefix must be rejected by the AMCL drivers.
func TestG1InvalidPrefixRejected(t *testing.T) {
	for _, id := range []CurveID{FP256BN_AMCL, FP256BN_AMCL_MIRACL} {
		c := Curves[id]
		t.Run(CurveIDToString(id), func(t *testing.T) {
			for _, prefix := range []byte{0x00, 0x01, 0x05, 0xff} {
				b := c.GenG1.Bytes()
				b[0] = prefix
				_, err := c.NewG1FromBytes(b)
				require.Error(t, err, "prefix 0x%02x", prefix)

				b = c.GenG1.Compressed()
				b[0] = prefix
				_, err = c.NewG1FromCompressed(b)
				require.Error(t, err, "prefix 0x%02x", prefix)
			}
		})
	}
}

// The canonical encodings of the identity and of valid points must keep
// round-tripping on every curve and in every format.
func TestPointRoundTrip(t *testing.T) {
	for _, c := range Curves {
		t.Run(CurveIDToString(c.ID()), func(t *testing.T) {
			rng, err := c.Rand()
			require.NoError(t, err)
			r := c.NewRandomZr(rng)

			for _, p := range []*G1{c.NewG1(), c.GenG1, c.GenG1.Mul(r)} {
				q, err := c.NewG1FromBytes(p.Bytes())
				require.NoError(t, err)
				require.True(t, q.Equals(p))
				require.Equal(t, p.IsInfinity(), q.IsInfinity())

				q, err = c.NewG1FromCompressed(p.Compressed())
				require.NoError(t, err)
				require.True(t, q.Equals(p))
			}

			for _, p := range []*G2{c.NewG2(), c.GenG2, c.GenG2.Mul(r)} {
				q, err := c.NewG2FromBytes(p.Bytes())
				require.NoError(t, err)
				require.True(t, q.Equals(p))

				q, err = c.NewG2FromCompressed(p.Compressed())
				require.NoError(t, err)
				require.True(t, q.Equals(p))
			}

			for _, g := range []*Gt{c.GenGt.Exp(c.NewZrFromInt(0)), c.GenGt, c.GenGt.Exp(r)} {
				h, err := c.NewGtFromBytes(g.Bytes())
				require.NoError(t, err)
				require.True(t, h.Equals(g))
			}
		})
	}
}

// Points on the FP256BN sextic twist (x = 1 + 0*i) that are not in the
// order-r subgroup G2 must be rejected.
var (
	// FP256BN_AMCL G2 layout: Xa||Xb||Ya||Yb (4*32 bytes).
	fp256bnTwistPointNotInG2 = "0000000000000000000000000000000000000000000000000000000000000001" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"c8931067e59cbf08d406b44ddde32960f67bcad8fe69bc5e469e9ba74ccc1225" +
		"a646cec84f20954d589dba3331ab71ba4321d1663c8aea6da59fb69d261559ca"
	// FP256BN_AMCL_MIRACL G2 layout: 0x04||Xb||Xa||Yb||Ya.
	fp256bnMiraclTwistPointNotInG2 = "04" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000001" +
		"59b93137b0dc5b7fee48382bbcc632e4c9ba9494d60d20152d89773e88bdd649" +
		"376cef981a6031c472df3e11108e7b3e16609b22142e4e248c8a923462071dee"
)

func TestG2SubgroupCheck(t *testing.T) {
	cases := map[CurveID]string{
		FP256BN_AMCL:        fp256bnTwistPointNotInG2,
		FP256BN_AMCL_MIRACL: fp256bnMiraclTwistPointNotInG2,
	}
	for id, h := range cases {
		c := Curves[id]
		raw, err := hex.DecodeString(h)
		require.NoError(t, err)
		t.Run(CurveIDToString(id), func(t *testing.T) {
			_, err := c.NewG2FromBytes(raw)
			require.Error(t, err)

			_, err = c.NewG2FromCompressed(raw)
			require.Error(t, err)
		})
	}

	// The MIRACL driver also has a genuinely compressed G2 format.
	c := Curves[FP256BN_AMCL_MIRACL]
	raw, err := hex.DecodeString(fp256bnMiraclTwistPointNotInG2)
	require.NoError(t, err)
	comp := append([]byte{0x02}, raw[1:1+2*32]...)
	_, err1 := c.NewG2FromCompressed(comp)
	comp[0] = 0x03
	_, err2 := c.NewG2FromCompressed(comp)
	require.Error(t, err1)
	require.Error(t, err2)
}

// Point decoders must require the exact length of the requested format.
func TestPointWrongLengthRejected(t *testing.T) {
	for _, c := range Curves {
		t.Run(CurveIDToString(c.ID()), func(t *testing.T) {
			for _, p := range []*G1{c.GenG1, c.NewG1()} {
				_, err := c.NewG1FromBytes(append(p.Bytes(), 0x01))
				require.Error(t, err)
				_, err = c.NewG1FromBytes(p.Bytes()[:c.G1ByteSize-1])
				require.Error(t, err)
				_, err = c.NewG1FromCompressed(append(p.Compressed(), 0x01))
				require.Error(t, err)
				_, err = c.NewG1FromCompressed(p.Compressed()[:c.CompressedG1ByteSize-1])
				require.Error(t, err)
			}
			for _, p := range []*G2{c.GenG2, c.NewG2()} {
				_, err := c.NewG2FromBytes(append(p.Bytes(), 0x01))
				require.Error(t, err)
				_, err = c.NewG2FromBytes(p.Bytes()[:c.G2ByteSize-1])
				require.Error(t, err)
				_, err = c.NewG2FromCompressed(append(p.Compressed(), 0x01))
				require.Error(t, err)
				_, err = c.NewG2FromCompressed(p.Compressed()[:c.CompressedG2ByteSize-1])
				require.Error(t, err)
			}

			_, err := c.NewGtFromBytes(append(c.GenGt.Bytes(), 0x01))
			require.Error(t, err)
			_, err = c.NewG1FromBytes(nil)
			require.Error(t, err)
			_, err = c.NewG2FromCompressed(nil)
			require.Error(t, err)

			if c.G1ByteSize != c.CompressedG1ByteSize {
				_, err = c.NewG1FromBytes(c.GenG1.Compressed())
				require.Error(t, err, "NewG1FromBytes accepted a compressed encoding")
				_, err = c.NewG1FromCompressed(c.GenG1.Bytes())
				require.Error(t, err, "NewG1FromCompressed accepted an uncompressed encoding")
			}
			if c.G2ByteSize != c.CompressedG2ByteSize {
				_, err = c.NewG2FromBytes(c.GenG2.Compressed())
				require.Error(t, err, "NewG2FromBytes accepted a compressed encoding")
				_, err = c.NewG2FromCompressed(c.GenG2.Bytes())
				require.Error(t, err, "NewG2FromCompressed accepted an uncompressed encoding")
			}
		})
	}
}

// String must not panic on the identity elements.
func TestStringOnIdentity(t *testing.T) {
	for _, c := range Curves {
		t.Run(CurveIDToString(c.ID()), func(t *testing.T) {
			require.NotPanics(t, func() { _ = c.NewG1().String() })
			require.NotPanics(t, func() { _ = c.NewG2().String() })
			require.NotPanics(t, func() { _ = c.GenGt.Exp(c.NewZrFromInt(0)).String() })
			require.NotEmpty(t, c.NewG1().String())
			require.NotEqual(t, c.NewG1().String(), c.GenG1.String())
		})
	}
}

// Zr comparisons must be modular on every curve.
func TestZrEqualsModular(t *testing.T) {
	for _, c := range Curves {
		t.Run(CurveIDToString(c.ID()), func(t *testing.T) {
			q := orderOf(c)
			zero := c.NewZrFromInt(0)
			one := c.NewZrFromInt(1)

			zq := c.NewZrFromBytes(enc32(q))
			require.True(t, zq.IsZero())
			require.True(t, zq.Equals(zero))
			require.True(t, zero.Equals(zq))
			require.False(t, zq.IsOne())

			zq1 := c.NewZrFromBytes(enc32(new(big.Int).Add(q, big.NewInt(1))))
			require.True(t, zq1.IsOne())
			require.True(t, zq1.Equals(one))
			require.False(t, zq1.IsZero())

			minus1 := c.NewZrFromInt(-1)
			qm1 := c.NewZrFromBytes(enc32(new(big.Int).Sub(q, big.NewInt(1))))
			require.True(t, minus1.Equals(qm1))
			require.True(t, qm1.Equals(minus1))
			require.False(t, minus1.IsOne())

			minusQPlus1 := c.NewZrFromBigInt(new(big.Int).Sub(big.NewInt(1), q))
			require.True(t, minusQPlus1.IsOne())

			a := c.NewZrFromInt(5)
			b := c.NewZrFromInt(5)
			b.Neg()
			require.True(t, a.Plus(b).IsZero())
			require.False(t, a.Equals(b))

			// GroupOrder keeps its documented raw value.
			require.Equal(t, enc32(q), c.GroupOrder.Bytes())
			require.False(t, c.GroupOrder.IsZero())
		})
	}
}

// Bytes of a Zr equal to q must be the canonical encoding of 0.
func TestZrBytesOfOrderReduced(t *testing.T) {
	for _, c := range Curves {
		t.Run(CurveIDToString(c.ID()), func(t *testing.T) {
			z := c.NewZrFromBigInt(orderOf(c))
			require.Equal(t, make([]byte, c.ScalarByteSize), z.Bytes())

			z = c.NewZrFromBytes(enc32(orderOf(c)))
			require.Equal(t, make([]byte, c.ScalarByteSize), z.Bytes())
		})
	}
}

// NewZrFromBytesCanonical must accept exactly the encodings produced by Bytes.
func TestNewZrFromBytesCanonical(t *testing.T) {
	for _, c := range Curves {
		t.Run(CurveIDToString(c.ID()), func(t *testing.T) {
			q := orderOf(c)
			rng, err := c.Rand()
			require.NoError(t, err)

			for _, z := range []*Zr{c.NewZrFromInt(0), c.NewZrFromInt(1), c.NewZrFromInt(-1), c.NewRandomZr(rng)} {
				b := z.Bytes()
				w, err := c.NewZrFromBytesCanonical(b)
				require.NoError(t, err)
				require.True(t, w.Equals(z))
				require.Equal(t, b, w.Bytes())
				require.Equal(t, c.ID(), w.CurveID())
			}

			bad := map[string][]byte{
				"q":                           enc32(q),
				"q+1":                         enc32(new(big.Int).Add(q, big.NewInt(1))),
				"all ones":                    bytes.Repeat([]byte{0xff}, 32),
				"1 left-padded to 33 bytes":   append([]byte{0x00}, enc32(big.NewInt(1))...),
				"1 as a single byte":          {0x01},
				"empty slice":                 {},
				"nil":                         nil,
				"64 bytes (2*ScalarByteSize)": bytes.Repeat([]byte{0x00}, 64),
			}
			for name, in := range bad {
				_, err := c.NewZrFromBytesCanonical(in)
				require.Error(t, err, name)
			}

			// NewZrFromBytes keeps its lenient, reducing semantics.
			require.True(t, c.NewZrFromBytes(enc32(new(big.Int).Add(q, big.NewInt(1)))).IsOne())
			require.True(t, c.NewZrFromBytes([]byte{0x01}).IsOne())
		})
	}
}

// Clone must preserve the sign of the source.
func TestZrClonePreservesSign(t *testing.T) {
	for _, c := range Curves {
		t.Run(CurveIDToString(c.ID()), func(t *testing.T) {
			z := c.NewZrFromInt(5)
			z.Neg()

			w := c.NewZrFromInt(0)
			w.Clone(z)

			require.True(t, w.Equals(z))
			require.True(t, c.GenG1.Mul(w).Equals(c.GenG1.Mul(z)))

			w = c.NewZrFromInt(0)
			w.Clone(c.GroupOrder)
			require.Equal(t, c.GroupOrder.Bytes(), w.Bytes())
		})
	}
}

// NewZrFromBigInt must not alias the caller's big.Int.
func TestZrFromBigIntNoAlias(t *testing.T) {
	for _, c := range Curves {
		t.Run(CurveIDToString(c.ID()), func(t *testing.T) {
			i := new(big.Int).Lsh(big.NewInt(1), 200)
			z := c.NewZrFromBigInt(i)
			before := z.Bytes()

			i.SetUint64(7) // reuses i's backing array

			require.Equal(t, before, z.Bytes())
		})
	}
}

// Exponentiation by any multiple of q (including 0) must yield unity.
func TestGtExpZero(t *testing.T) {
	for _, c := range Curves {
		t.Run(CurveIDToString(c.ID()), func(t *testing.T) {
			require.True(t, c.GenGt.Exp(c.NewZrFromInt(0)).IsUnity())

			rng, err := c.Rand()
			require.NoError(t, err)
			g := c.GenGt.Exp(c.NewRandomZr(rng))
			require.True(t, g.Exp(c.NewZrFromInt(0)).IsUnity())
			require.True(t, g.Exp(c.NewZrFromBigInt(orderOf(c))).IsUnity())
			require.True(t, g.Exp(c.GroupOrder).IsUnity())
			require.True(t, g.Exp(c.NewZrFromInt(1)).Equals(g))
		})
	}
}

// NewGtFromBytes must reject Fp12 elements outside the order-r subgroup.
func TestGtFromBytesSubgroupCheck(t *testing.T) {
	for _, c := range Curves {
		t.Run(CurveIDToString(c.ID()), func(t *testing.T) {
			size := len(c.GenGt.Bytes())

			raw := bytes.Repeat([]byte{0x01}, size)
			_, err := c.NewGtFromBytes(raw)
			require.Error(t, err)

			// The (unreduced) output of a Miller loop is not in Gt in general.
			ml := c.Pairing(c.GenG2, c.GenG1)
			if !ml.Equals(c.GenGt) {
				_, err = c.NewGtFromBytes(ml.Bytes())
				require.Error(t, err)
			}

			_, err = c.NewGtFromBytes(make([]byte, size))
			require.Error(t, err, "zero is not a Gt element")
		})
	}
}
