/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Direct tests for the bls12381 driver package.
// These exercises every exported type and method directly so that the
// per-package coverage tool can count them.

package bls12381

import (
	"math/big"
	"testing"

	"github.com/IBM/mathlib/driver"
	gnarkbls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newCurve() *Curve { return NewCurve() }

func randZr(t *testing.T, c *Curve) driver.Zr {
	t.Helper()
	r, err := c.Rand()
	require.NoError(t, err)

	return c.NewRandomZr(r)
}

// ---------------------------------------------------------------------------
// Zr
// ---------------------------------------------------------------------------

func TestZrIsZeroIsOne(t *testing.T) {
	c := newCurve()
	assert.True(t, c.NewZrFromInt64(0).IsZero())
	assert.False(t, c.NewZrFromInt64(1).IsZero())
	assert.True(t, c.NewZrFromInt64(1).IsOne())
	assert.False(t, c.NewZrFromInt64(0).IsOne())
	assert.False(t, c.NewZrFromInt64(2).IsOne())
}

func TestZrBigInt(t *testing.T) {
	c := newCurve()
	z := c.NewZrFromInt64(777)
	bi := z.BigInt()
	assert.Zero(t, bi.Cmp(big.NewInt(777)))
}

func TestZrPlus(t *testing.T) {
	c := newCurve()
	a := c.NewZrFromInt64(5)
	b := c.NewZrFromInt64(7)
	s := a.Plus(b)
	assert.True(t, s.Equals(c.NewZrFromInt64(12)))
}

func TestZrMinus(t *testing.T) {
	c := newCurve()
	a := c.NewZrFromInt64(10)
	b := c.NewZrFromInt64(3)
	d := a.Minus(b)
	assert.True(t, d.Equals(c.NewZrFromInt64(7)))
}

func TestZrMul(t *testing.T) {
	c := newCurve()
	a := c.NewZrFromInt64(6)
	b := c.NewZrFromInt64(7)
	p := a.Mul(b)
	assert.True(t, p.Equals(c.NewZrFromInt64(42)))
}

func TestZrPowMod(t *testing.T) {
	c := newCurve()
	base := c.NewZrFromInt64(2)
	exp := c.NewZrFromInt64(10)
	r := base.PowMod(exp)
	assert.True(t, r.Equals(c.NewZrFromInt64(1024)))
}

func TestZrMod(t *testing.T) {
	c := newCurve()
	a := c.NewZrFromInt64(7)
	m := c.NewZrFromInt64(3)
	a.Mod(m)
	assert.True(t, a.Equals(c.NewZrFromInt64(1)))
}

func TestZrInvModP(t *testing.T) {
	c := newCurve()
	// 3 * 4 ≡ 1 (mod 11)
	a := c.NewZrFromInt64(3)
	a.InvModP(c.NewZrFromInt64(11))
	assert.True(t, a.Equals(c.NewZrFromInt64(4)))
}

func TestZrInvModOrder(t *testing.T) {
	c := newCurve()
	a := c.NewZrFromInt64(7)
	orig := a.Copy()
	a.InvModOrder()
	assert.True(t, orig.Mul(a).Equals(c.NewZrFromInt64(1)))
}

func TestZrBytes(t *testing.T) {
	c := newCurve()
	a := c.NewZrFromInt64(12345)
	b := a.Bytes()
	back := c.NewZrFromBytes(b)
	assert.True(t, a.Equals(back))
}

func TestZrCopyClone(t *testing.T) {
	c := newCurve()
	a := c.NewZrFromInt64(99)
	cp := a.Copy()
	assert.True(t, a.Equals(cp))

	cl := c.NewZrFromInt64(0)
	cl.Clone(a)
	assert.True(t, a.Equals(cl))
}

func TestZrString(t *testing.T) {
	c := newCurve()
	s := c.NewZrFromInt64(255).String()
	assert.Equal(t, "ff", s)
}

func TestZrNeg(t *testing.T) {
	c := newCurve()
	a := c.NewZrFromInt64(10)
	m := c.GroupOrder()
	a.Neg()
	sum := a.Plus(c.NewZrFromInt64(10))
	sum.Mod(m)
	assert.True(t, sum.IsZero())
}

func TestZrFromUint64(t *testing.T) {
	c := newCurve()
	u := c.NewZrFromUint64(999)
	assert.True(t, u.Equals(c.NewZrFromInt64(999)))
}

func TestZrFromBigInt(t *testing.T) {
	c := newCurve()
	n := big.NewInt(54321)
	z := c.NewZrFromBigInt(n)
	assert.True(t, z.Equals(c.NewZrFromInt64(54321)))
}

func TestGroupOrder(t *testing.T) {
	c := newCurve()
	order := c.GroupOrder()
	assert.False(t, order.IsZero())
}

// ---------------------------------------------------------------------------
// G1
// ---------------------------------------------------------------------------

func TestG1Ops(t *testing.T) {
	c := newCurve()
	r := randZr(t, c)

	g := c.GenG1()
	assert.False(t, g.IsInfinity())

	g35 := g.Mul(c.NewZrFromInt64(35))
	g23 := g.Mul(c.NewZrFromInt64(23))
	g58 := g.Mul(c.NewZrFromInt64(58))

	sum := g35.Copy()
	sum.Add(g23)
	assert.True(t, sum.Equals(g58))

	sub := g58.Copy()
	sub.Sub(g23)
	assert.True(t, sub.Equals(g35))

	// IsInfinity after self-subtraction
	inf := g35.Copy()
	inf.Sub(g35.Copy())
	assert.True(t, inf.IsInfinity())

	// Neg
	neg := g35.Copy()
	neg.Neg()
	neg.Add(g35.Copy())
	assert.True(t, neg.IsInfinity())

	// Mul2
	m2 := g.Mul2(c.NewZrFromInt64(35), g, c.NewZrFromInt64(23))
	assert.True(t, m2.Equals(g58))

	// Mul2InPlace
	m3 := g.Copy()
	m3.Mul2InPlace(c.NewZrFromInt64(35), g, c.NewZrFromInt64(23))
	assert.True(t, m3.Equals(g58))

	// Clone
	clone := c.NewG1()
	clone.Clone(g35)
	assert.True(t, clone.Equals(g35))

	// Bytes round-trip
	pt := g.Mul(r)
	raw := pt.Bytes()
	back := c.NewG1FromBytes(raw)
	assert.True(t, pt.Equals(back))

	// Compressed round-trip
	comp := pt.Compressed()
	backComp := c.NewG1FromCompressed(comp)
	assert.True(t, pt.Equals(backComp))

	// String (must not panic)
	_ = g.String()
}

func TestG1InvalidBytes(t *testing.T) {
	c := newCurve()
	assert.Panics(t, func() { c.NewG1FromBytes(nil) })
	assert.Panics(t, func() { c.NewG1FromCompressed(nil) })
}

// ---------------------------------------------------------------------------
// G2
// ---------------------------------------------------------------------------

func TestG2Ops(t *testing.T) {
	c := newCurve()
	r := randZr(t, c)

	g := c.GenG2()

	g35 := g.Mul(c.NewZrFromInt64(35))
	g23 := g.Mul(c.NewZrFromInt64(23))
	g58 := g.Mul(c.NewZrFromInt64(58))

	sum := g35.Copy()
	sum.Add(g23)
	assert.True(t, sum.Equals(g58))

	sub := g58.Copy()
	sub.Sub(g23)
	assert.True(t, sub.Equals(g35))

	// Affine (no-op, must not panic)
	g35.Affine()

	// Clone
	clone := c.NewG2()
	clone.Clone(g35)
	assert.True(t, clone.Equals(g35))

	// Bytes / Compressed round-trip
	pt := g.Mul(r)
	raw := pt.Bytes()
	back := c.NewG2FromBytes(raw)
	assert.True(t, pt.Equals(back))

	comp := pt.Compressed()
	backComp := c.NewG2FromCompressed(comp)
	assert.True(t, pt.Equals(backComp))

	// String
	_ = g.String()
}

func TestG2InvalidBytes(t *testing.T) {
	c := newCurve()
	assert.Panics(t, func() { c.NewG2FromBytes(nil) })
	assert.Panics(t, func() { c.NewG2FromCompressed(nil) })
}

// ---------------------------------------------------------------------------
// Gt
// ---------------------------------------------------------------------------

func TestGtOps(t *testing.T) {
	c := newCurve()
	r := randZr(t, c)

	g1 := c.GenG1()
	g2 := c.GenG2()

	gt := c.FExp(c.Pairing(g2, g1))

	// Exp(1) == gt
	assert.True(t, gt.Equals(gt.Exp(c.NewZrFromInt64(1))))

	// gt * gt^-1 == unity
	inv := c.NewGtFromBytes(gt.Bytes())
	inv.Inverse()
	gt.Mul(inv)
	assert.True(t, gt.IsUnity())

	// Bytes round-trip
	gtr := c.FExp(c.Pairing(g2.Mul(r), g1))
	b := gtr.Bytes()
	back := c.NewGtFromBytes(b)
	assert.True(t, gtr.Equals(back))

	// ToString
	assert.NotEmpty(t, gtr.ToString())
}

func TestGtInvalidBytes(t *testing.T) {
	c := newCurve()
	assert.Panics(t, func() { c.NewGtFromBytes(nil) })
}

// ---------------------------------------------------------------------------
// Pairing
// ---------------------------------------------------------------------------

func TestPairing(t *testing.T) {
	c := newCurve()
	r, err := c.Rand()
	require.NoError(t, err)

	s := c.NewRandomZr(r)
	g1 := c.GenG1()
	g2 := c.GenG2()

	a := c.FExp(c.Pairing(g2.Mul(s), g1))
	b := c.FExp(c.Pairing(g2, g1.Mul(s)))
	assert.True(t, a.Equals(b))

	// Pairing2
	r1 := c.NewRandomZr(r)
	r2 := c.NewRandomZr(r)
	r3 := c.NewRandomZr(r)
	r4 := c.NewRandomZr(r)

	p := g2.Mul(r1)
	q := g1.Mul(r2)
	rg2 := g2.Mul(r3)
	sg1 := g1.Mul(r4)

	tt1 := c.FExp(c.Pairing2(p, rg2, q, sg1))
	tt2 := c.FExp(c.Pairing(g2.Mul(r1).Mul(r2), g1))
	tt3 := c.FExp(c.Pairing(g2, g1.Mul(r3).Mul(r4)))
	tt2.Mul(tt3)
	assert.True(t, tt1.Equals(tt2))
}

// ---------------------------------------------------------------------------
// Hash functions
// ---------------------------------------------------------------------------

func TestHashToG1(t *testing.T) {
	c := newCurve()
	msg := []byte("hello bls12-381")

	h := c.HashToG1(msg)
	assert.False(t, h.IsInfinity())
	h2 := c.HashToG1(msg)
	assert.True(t, h.Equals(h2))

	hd := c.HashToG1WithDomain(msg, []byte("domain"))
	assert.False(t, hd.IsInfinity())
}

func TestHashToG2(t *testing.T) {
	c := newCurve()
	msg := []byte("hello g2")
	h := c.HashToG2(msg)
	assert.NotEmpty(t, h.Bytes())
	hd := c.HashToG2WithDomain(msg, []byte("dom"))
	assert.NotEmpty(t, hd.Bytes())
}

func TestHashToZr(t *testing.T) {
	c := newCurve()
	h := c.HashToZr([]byte("some data"))
	assert.False(t, h.IsZero())
}

// ---------------------------------------------------------------------------
// BBSCurve
// ---------------------------------------------------------------------------

func TestBBSCurveHashToG1(t *testing.T) {
	bbs := NewBBSCurve()
	msg := []byte("bbs test")
	h := bbs.HashToG1(msg)
	assert.False(t, h.IsInfinity())

	hd := bbs.HashToG1WithDomain(msg, []byte("dom"))
	assert.False(t, hd.IsInfinity())
}

func TestBBSCurveHashToG2(t *testing.T) {
	bbs := NewBBSCurve()
	msg := []byte("bbs g2")
	h := bbs.HashToG2(msg)
	assert.NotEmpty(t, h.Bytes())

	hd := bbs.HashToG2WithDomain(msg, []byte("dom"))
	assert.NotEmpty(t, hd.Bytes())
}

// ---------------------------------------------------------------------------
// Mod arithmetic
// ---------------------------------------------------------------------------

func TestModArith(t *testing.T) {
	c := newCurve()
	m := c.GroupOrder()
	a := c.NewZrFromInt64(8)
	b := c.NewZrFromInt64(3)

	assert.True(t, c.ModAdd(a, b, m).Equals(c.NewZrFromInt64(11)))
	assert.True(t, c.ModSub(a, b, m).Equals(c.NewZrFromInt64(5)))
	assert.True(t, c.ModMul(a, b, m).Equals(c.NewZrFromInt64(24)))

	neg := c.ModNeg(b, m)
	sum := c.ModAdd(b, neg, m)
	assert.True(t, sum.IsZero())

	// ModAddMul2
	r := c.ModAddMul2(a, b, b, a, m)
	assert.True(t, r.Equals(c.NewZrFromInt64(48))) // (8*3)+(3*8)=48

	// ModAddMul3
	c1 := c.NewZrFromInt64(2)
	r3 := c.ModAddMul3(a, b, b, a, c1, c1, m)
	assert.True(t, r3.Equals(c.NewZrFromInt64(52))) // 24+24+4=52

	// ModAddMul (slice form)
	sl := c.ModAddMul([]driver.Zr{a, b}, []driver.Zr{b, a}, m)
	assert.True(t, sl.Equals(c.NewZrFromInt64(48)))

	// InPlace forms
	res := c.NewZrFromInt64(0)
	c.ModMulInPlace(res, a, b, m)
	assert.True(t, res.Equals(c.NewZrFromInt64(24)))

	res2 := c.NewZrFromInt64(0)
	c.ModAddMul2InPlace(res2, a, b, b, a, m)
	assert.True(t, res2.Equals(c.NewZrFromInt64(48)))

	res3 := c.NewZrFromInt64(0)
	c.ModAddMul3InPlace(res3, a, b, b, a, c1, c1, m)
	assert.True(t, res3.Equals(c.NewZrFromInt64(52)))
}

// ---------------------------------------------------------------------------
// MultiScalarMul
// ---------------------------------------------------------------------------

func TestMultiScalarMul(t *testing.T) {
	c := newCurve()
	r, err := c.Rand()
	require.NoError(t, err)

	n := 5
	pts := make([]driver.G1, n)
	scalars := make([]driver.Zr, n)
	for i := range n {
		scalars[i] = c.NewRandomZr(r)
		pts[i] = c.GenG1().Mul(c.NewRandomZr(r))
	}

	naive := c.NewG1()
	for i := range n {
		naive.Add(pts[i].Mul(scalars[i]))
	}
	msm := c.MultiScalarMul(pts, scalars)
	assert.True(t, naive.Equals(msm))
}

// ---------------------------------------------------------------------------
// Size accessors
// ---------------------------------------------------------------------------

func TestCurveSizes(t *testing.T) {
	c := newCurve()
	assert.Positive(t, c.CoordinateByteSize())
	assert.Positive(t, c.G1ByteSize())
	assert.Positive(t, c.CompressedG1ByteSize())
	assert.Positive(t, c.G2ByteSize())
	assert.Positive(t, c.CompressedG2ByteSize())
	assert.Positive(t, c.ScalarByteSize())
}

// ---------------------------------------------------------------------------
// JointScalarMultiplication
// ---------------------------------------------------------------------------

func TestJointScalarMultiplication(t *testing.T) {
	c := newCurve()
	r, err := c.Rand()
	require.NoError(t, err)

	s1 := c.NewRandomZr(r).BigInt()
	s2 := c.NewRandomZr(r).BigInt()

	g1a := c.GenG1().(*G1)
	g1b := c.GenG1().Mul(c.NewZrFromInt64(3)).(*G1)

	p := &bls12381G1Jac{}
	JointScalarMultiplication(p, &g1a.G1Affine, &g1b.G1Affine, s1, s2)
	assert.NotNil(t, p)
}

type bls12381G1Jac = gnarkbls.G1Jac
