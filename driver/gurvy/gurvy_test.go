/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package-level tests for the gurvy driver: bn254 and bls12-377 curves.
// These tests exercise the driver types directly (G1, G2, Gt, Zr, Curve)
// without going through the top-level math package.

package gurvy

import (
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"io"
	"testing"

	"github.com/IBM/mathlib/driver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type curveDriver interface {
	driver.Curve
	GenG1() driver.G1
	GenG2() driver.G2
	GenGt() driver.Gt
}

func randomZr(t *testing.T, c driver.Curve) driver.Zr {
	t.Helper()
	rng, err := c.Rand()
	require.NoError(t, err)
	return c.NewRandomZr(rng)
}

// ---------------------------------------------------------------------------
// Shared curve test suite — run once for each driver.
// ---------------------------------------------------------------------------

func runDriverSuite(t *testing.T, c curveDriver) {
	t.Helper()
	t.Run("Rand", func(t *testing.T) {
		rng, err := c.Rand()
		require.NoError(t, err)
		assert.NotNil(t, rng)
	})
	t.Run("GroupOrder", func(t *testing.T) {
		order := c.GroupOrder()
		assert.NotNil(t, order)
		assert.False(t, order.IsZero())
	})
	t.Run("Zr_ops", func(t *testing.T) { testZrOps(t, c) })
	t.Run("G1_ops", func(t *testing.T) { testG1Ops(t, c) })
	t.Run("G2_ops", func(t *testing.T) { testG2Ops(t, c) })
	t.Run("Gt_ops", func(t *testing.T) { testGtOps(t, c) })
	t.Run("Pairing", func(t *testing.T) { testPairing(t, c) })
	t.Run("HashToG1", func(t *testing.T) { testHashToG1(t, c) })
	t.Run("Serialisation", func(t *testing.T) { testSerialisation(t, c) })
	t.Run("ModArith", func(t *testing.T) { testModArith(t, c) })
	t.Run("MultiScalarMul", func(t *testing.T) { testMultiScalarMul(t, c) })
}

func testZrOps(t *testing.T, c curveDriver) {
	t.Helper()
	rng, err := c.Rand()
	require.NoError(t, err)

	// NewZrFromInt64 / NewZrFromUint64 / NewZrFromBytes
	a := c.NewZrFromInt64(7)
	b := c.NewZrFromUint64(3)
	assert.False(t, a.IsZero())
	assert.False(t, b.IsZero())
	assert.True(t, c.NewZrFromInt64(0).IsZero())
	assert.True(t, c.NewZrFromInt64(1).IsOne())
	assert.False(t, c.NewZrFromInt64(2).IsOne())

	// Plus / Minus / Mul / PowMod
	sum := a.Plus(b)
	assert.True(t, sum.Equals(c.NewZrFromInt64(10)))
	diff := a.Minus(b)
	assert.True(t, diff.Equals(c.NewZrFromInt64(4)))
	prod := a.Mul(b)
	assert.True(t, prod.Equals(c.NewZrFromInt64(21)))

	// Mod
	m := c.NewZrFromInt64(5)
	am := a.Copy()
	am.Mod(m)
	assert.True(t, am.Equals(c.NewZrFromInt64(2)))

	// InvModP: 3 * 4 == 1 (mod 11)
	three := c.NewZrFromInt64(3)
	three.InvModP(c.NewZrFromInt64(11))
	assert.True(t, three.Equals(c.NewZrFromInt64(4)))

	// InvModOrder
	r := c.NewRandomZr(rng)
	rInv := r.Copy()
	rInv.InvModOrder()
	assert.True(t, r.Mul(rInv).Equals(c.NewZrFromInt64(1)))

	// PowMod: 2^10 = 1024
	base := c.NewZrFromInt64(2)
	pow := base.PowMod(c.NewZrFromInt64(10))
	assert.True(t, pow.Equals(c.NewZrFromInt64(1024)))

	// Bytes round-trip
	rr := c.NewRandomZr(rng)
	back := c.NewZrFromBytes(rr.Bytes())
	assert.True(t, rr.Equals(back))

	// BigInt
	bi := c.NewZrFromInt64(999).BigInt()
	assert.NotNil(t, bi)

	// Clone / Copy
	x := c.NewZrFromInt64(55)
	y := x.Copy()
	assert.True(t, x.Equals(y))
	z := c.NewZrFromInt64(0)
	z.Clone(x)
	assert.True(t, x.Equals(z))

	// String
	s := c.NewZrFromInt64(255).String()
	assert.Equal(t, "ff", s)

	// Neg: x + (-x) mod p == 0
	n := c.NewRandomZr(rng)
	neg := n.Copy()
	neg.Neg()
	sum2 := n.Plus(neg)
	sum2.Mod(c.GroupOrder())
	assert.True(t, sum2.IsZero())
}

func testG1Ops(t *testing.T, c curveDriver) {
	t.Helper()
	rng, err := c.Rand()
	require.NoError(t, err)
	r := c.NewRandomZr(rng)

	g := c.GenG1()
	assert.False(t, g.IsInfinity())

	// Mul: [35]g
	g35 := g.Mul(c.NewZrFromInt64(35))
	g23 := g.Mul(c.NewZrFromInt64(23))
	g58 := g.Mul(c.NewZrFromInt64(58))

	sum := g35.Copy()
	sum.Add(g23)
	assert.True(t, sum.Equals(g58))

	// Sub
	sub := g58.Copy()
	sub.Sub(g23)
	assert.True(t, sub.Equals(g35))

	// IsInfinity after self-subtraction
	self := g35.Copy()
	self.Sub(g35.Copy())
	assert.True(t, self.IsInfinity())

	// Neg
	neg := g35.Copy()
	neg.Neg()
	neg.Add(g35.Copy())
	assert.True(t, neg.IsInfinity())

	// Mul2: [35]g + [23]g == [58]g
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
	raw := g.Mul(r).Bytes()
	back := c.NewG1FromBytes(raw)
	assert.Equal(t, raw, back.Bytes())

	// Compressed round-trip
	comp := g.Mul(r).Compressed()
	backComp := c.NewG1FromCompressed(comp)
	assert.Equal(t, comp, backComp.Compressed())

	// String (just must not panic)
	_ = g.String()
}

func testG2Ops(t *testing.T, c curveDriver) {
	t.Helper()
	rng, err := c.Rand()
	require.NoError(t, err)
	r := c.NewRandomZr(rng)

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

	// Affine (no-op for gnark-crypto, just must not panic)
	g35.Affine()

	// Clone
	clone := c.NewG2()
	clone.Clone(g35)
	assert.True(t, clone.Equals(g35))

	// Bytes round-trip
	raw := g.Mul(r).Bytes()
	back := c.NewG2FromBytes(raw)
	assert.Equal(t, raw, back.Bytes())

	// Compressed round-trip
	comp := g.Mul(r).Compressed()
	backComp := c.NewG2FromCompressed(comp)
	assert.Equal(t, comp, backComp.Compressed())

	// String
	_ = g.String()
}

func testGtOps(t *testing.T, c curveDriver) {
	t.Helper()
	rng, err := c.Rand()
	require.NoError(t, err)

	g1 := c.GenG1()
	g2 := c.GenG2()

	gt := c.Pairing(g2, g1)
	gt = c.FExp(gt)

	// Exp(1) == gt
	gt1 := gt.Exp(c.NewZrFromInt64(1))
	assert.True(t, gt.Equals(gt1))

	// Gt * Gt^-1 == unity
	// Clone via NewGtFromBytes since driver.Gt has no Copy()
	inv := c.NewGtFromBytes(gt.Bytes())
	inv.Inverse()
	gt.Mul(inv)
	assert.True(t, gt.IsUnity())

	// Bytes round-trip
	r := c.NewRandomZr(rng)
	gtr := c.Pairing(g2.Mul(r), g1)
	b := gtr.Bytes()
	back := c.NewGtFromBytes(b)
	assert.True(t, gtr.Equals(back))

	// ToString (driver.Gt has ToString, not String)
	s := gtr.ToString()
	assert.NotEmpty(t, s)
}

func testPairing(t *testing.T, c curveDriver) {
	t.Helper()
	rng, err := c.Rand()
	require.NoError(t, err)
	r := c.NewRandomZr(rng)

	g1 := c.GenG1()
	g2 := c.GenG2()

	// e([r]g2, g1) == e(g2, [r]g1)
	a := c.FExp(c.Pairing(g2.Mul(r), g1))
	b := c.FExp(c.Pairing(g2, g1.Mul(r)))
	assert.True(t, a.Equals(b))

	// Pairing2: Pairing2(p2a, p2b G2, p1a, p1b G1)
	r1 := c.NewRandomZr(rng)
	r2 := c.NewRandomZr(rng)
	r3 := c.NewRandomZr(rng)
	r4 := c.NewRandomZr(rng)

	p := g2.Mul(r1)
	q := g1.Mul(r2)
	rg2 := g2.Mul(r3)
	s := g1.Mul(r4)

	tt1 := c.FExp(c.Pairing2(p, rg2, q, s))
	tt2 := c.FExp(c.Pairing(g2.Mul(r1).Mul(r2), g1))
	tt3 := c.FExp(c.Pairing(g2, g1.Mul(r3).Mul(r4)))
	tt2.Mul(tt3)
	assert.True(t, tt1.Equals(tt2))
}

func testHashToG1(t *testing.T, c curveDriver) {
	t.Helper()
	msg := []byte("hash to g1 test")
	domain := []byte("domain")

	h1 := c.HashToG1(msg)
	assert.False(t, h1.IsInfinity())

	h2 := c.HashToG1WithDomain(msg, domain)
	assert.False(t, h2.IsInfinity())

	// deterministic
	h1b := c.HashToG1(msg)
	assert.True(t, h1.Equals(h1b))
}

func testSerialisation(t *testing.T, c curveDriver) {
	t.Helper()
	rng, err := c.Rand()
	require.NoError(t, err)
	r := c.NewRandomZr(rng)

	// G1 panic recovery — invalid bytes must panic (driver contract).
	assert.Panics(t, func() { c.NewG1FromBytes(nil) })
	assert.Panics(t, func() { c.NewG2FromBytes(nil) })
	assert.Panics(t, func() { c.NewG1FromCompressed(nil) })
	assert.Panics(t, func() { c.NewG2FromCompressed(nil) })
	assert.Panics(t, func() { c.NewGtFromBytes(nil) })

	// Valid round trips
	g1p := c.GenG1().Mul(r)
	g2p := c.GenG2().Mul(r)

	g1b := g1p.Bytes()
	assert.True(t, g1p.Equals(c.NewG1FromBytes(g1b)))
	g1c := g1p.Compressed()
	assert.True(t, g1p.Equals(c.NewG1FromCompressed(g1c)))

	g2b := g2p.Bytes()
	assert.True(t, g2p.Equals(c.NewG2FromBytes(g2b)))
	g2c := g2p.Compressed()
	assert.True(t, g2p.Equals(c.NewG2FromCompressed(g2c)))
}

func testModArith(t *testing.T, c curveDriver) {
	t.Helper()
	m := c.GroupOrder()

	a := c.NewZrFromInt64(8)
	b := c.NewZrFromInt64(3)

	// ModAdd
	sum := c.ModAdd(a, b, m)
	assert.True(t, sum.Equals(c.NewZrFromInt64(11)))

	// ModSub
	diff := c.ModSub(a, b, m)
	assert.True(t, diff.Equals(c.NewZrFromInt64(5)))

	// ModMul
	prod := c.ModMul(a, b, m)
	assert.True(t, prod.Equals(c.NewZrFromInt64(24)))

	// ModNeg
	neg := c.ModNeg(b, m)
	sum2 := c.ModAdd(b, neg, m)
	assert.True(t, sum2.IsZero())

	// ModAddMul2
	r := c.ModAddMul2(a, b, b, a, m)
	// (8*3) + (3*8) = 48
	assert.True(t, r.Equals(c.NewZrFromInt64(48)))

	// ModAddMul3
	c1 := c.NewZrFromInt64(2)
	r3 := c.ModAddMul3(a, b, b, a, c1, c1, m)
	// (8*3) + (3*8) + (2*2) = 52
	assert.True(t, r3.Equals(c.NewZrFromInt64(52)))

	// ModMulInPlace
	res := c.NewZrFromInt64(0)
	c.ModMulInPlace(res, a, b, m)
	assert.True(t, res.Equals(c.NewZrFromInt64(24)))

	// ModAddMul2InPlace
	res2 := c.NewZrFromInt64(0)
	c.ModAddMul2InPlace(res2, a, b, b, a, m)
	assert.True(t, res2.Equals(c.NewZrFromInt64(48)))

	// ModAddMul3InPlace
	res3 := c.NewZrFromInt64(0)
	c.ModAddMul3InPlace(res3, a, b, b, a, c1, c1, m)
	assert.True(t, res3.Equals(c.NewZrFromInt64(52)))
}

func testMultiScalarMul(t *testing.T, c curveDriver) {
	t.Helper()
	rng, err := c.Rand()
	require.NoError(t, err)

	n := 5
	pts := make([]driver.G1, n)
	scalars := make([]driver.Zr, n)
	for i := range n {
		scalars[i] = c.NewRandomZr(rng)
		pts[i] = c.GenG1().Mul(c.NewRandomZr(rng))
	}

	// Naïve sum
	naive := c.NewG1()
	for i := range n {
		naive.Add(pts[i].Mul(scalars[i]))
	}

	// MSM
	msm := c.MultiScalarMul(pts, scalars)
	assert.True(t, naive.Equals(msm))
}

// newG1DriverHelper is used by testSerialisation for HashToG1WithDomain.
// Some drivers (bn254 via driver interface) may not expose HashToG2WithDomain.
// We test what we can through the common interface.

// ---------------------------------------------------------------------------
// BN254
// ---------------------------------------------------------------------------

type bn254Driver struct {
	*Bn254
}

func (d *bn254Driver) GenG1() driver.G1 { return d.Bn254.GenG1() }
func (d *bn254Driver) GenG2() driver.G2 { return d.Bn254.GenG2() }
func (d *bn254Driver) GenGt() driver.Gt { return d.Bn254.GenGt() }

// NewG1 / NewG2 disambiguate between driver.Curve method and Bn254 method.
func (d *bn254Driver) NewG1() driver.G1 { return d.Bn254.NewG1() }
func (d *bn254Driver) NewG2() driver.G2 { return d.Bn254.NewG2() }

// Implement the full driver.Curve interface by delegating to Bn254.
var _ curveDriver = (*bn254Driver)(nil)

// Wrappers to satisfy the curveDriver interface's embedded methods that are
// not promoted automatically because of name clashes.

func (d *bn254Driver) Rand() (io.Reader, error) { return rand.Reader, nil }

func TestBn254Suite(t *testing.T) {
	runDriverSuite(t, &bn254Driver{NewBn254()})
}

// ---------------------------------------------------------------------------
// BLS12-377
// ---------------------------------------------------------------------------

type bls377Driver struct {
	*Bls12_377
}

func (d *bls377Driver) GenG1() driver.G1 { return d.Bls12_377.GenG1() }
func (d *bls377Driver) GenG2() driver.G2 { return d.Bls12_377.GenG2() }
func (d *bls377Driver) GenGt() driver.Gt { return d.Bls12_377.GenGt() }
func (d *bls377Driver) NewG1() driver.G1 { return d.Bls12_377.NewG1() }
func (d *bls377Driver) NewG2() driver.G2 { return d.Bls12_377.NewG2() }
func (d *bls377Driver) Rand() (io.Reader, error) { return rand.Reader, nil }

var _ curveDriver = (*bls377Driver)(nil)

func TestBls12377Suite(t *testing.T) {
	runDriverSuite(t, &bls377Driver{NewBls12_377()})
}

// ---------------------------------------------------------------------------
// BLS12-377 HashToG2
// ---------------------------------------------------------------------------

func TestBls12377HashToG2(t *testing.T) {
	c := NewBls12_377()
	msg := []byte("g2 hash")
	domain := []byte("dom")

	h := c.HashToG2(msg)
	// G2 has no IsInfinity; verify non-zero bytes as proxy.
	assert.NotEmpty(t, h.Bytes())

	h2 := c.HashToG2WithDomain(msg, domain)
	assert.NotEmpty(t, h2.Bytes())

	// The two hashes should differ (different domains would be tested elsewhere;
	// here just confirm the function runs without panic).
	assert.False(t, h.Equals(h2))
}

// ---------------------------------------------------------------------------
// Size accessors — smoke test for both drivers.
// ---------------------------------------------------------------------------

func TestBn254Sizes(t *testing.T) {
	c := NewBn254()
	assert.Positive(t, c.CoordinateByteSize())
	assert.Positive(t, c.G1ByteSize())
	assert.Positive(t, c.CompressedG1ByteSize())
	assert.Positive(t, c.G2ByteSize())
	assert.Positive(t, c.CompressedG2ByteSize())
	assert.Positive(t, c.ScalarByteSize())
}

func TestBls12377Sizes(t *testing.T) {
	c := NewBls12_377()
	assert.Positive(t, c.CoordinateByteSize())
	assert.Positive(t, c.G1ByteSize())
	assert.Positive(t, c.CompressedG1ByteSize())
	assert.Positive(t, c.G2ByteSize())
	assert.Positive(t, c.CompressedG2ByteSize())
	assert.Positive(t, c.ScalarByteSize())
}

// ---------------------------------------------------------------------------
// ExpandMsgXmd edge-case: ell > 255 must error.
// ---------------------------------------------------------------------------

func TestExpandMsgXmdEllTooBig(t *testing.T) {
	msg := []byte("test")
	dst := []byte("dst")
	// sha256 produces 32 bytes per block; 255*32 = 8160 bytes max.
	// Requesting 8161 bytes triggers ell > 255.
	_, err := ExpandMsgXmd(msg, dst, 256*32+1, newSHA256)
	assert.Error(t, err)
}

func TestExpandMsgXmdDstTooLong(t *testing.T) {
	msg := []byte("test")
	dst := make([]byte, 256)
	_, err := ExpandMsgXmd(msg, dst, 32, newSHA256)
	assert.Error(t, err)
}

// newSHA256 helper (used in ExpandMsgXmd tests).
func newSHA256() hash.Hash {
	return sha256.New()
}
