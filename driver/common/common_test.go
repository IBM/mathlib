/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"math/big"
	"testing"

	"github.com/IBM/mathlib/driver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// BigToBytes
// ---------------------------------------------------------------------------

func TestBigToBytesPositive(t *testing.T) {
	// A small positive number should be right-padded with zeroes to 32 bytes.
	n := big.NewInt(42)
	b := BigToBytes(n)
	assert.Len(t, b, ScalarByteSize)
	// Last byte must be 42.
	assert.Equal(t, byte(42), b[ScalarByteSize-1])
	// Leading bytes must be 0.
	for _, byt := range b[:ScalarByteSize-1] {
		assert.Equal(t, byte(0), byt)
	}
}

func TestBigToBytesZero(t *testing.T) {
	b := BigToBytes(big.NewInt(0))
	assert.Len(t, b, ScalarByteSize)
	for _, byt := range b {
		assert.Equal(t, byte(0), byt)
	}
}

func TestBigToBytesNegative(t *testing.T) {
	// -1 should produce the two's complement (0xFF…FF).
	b := BigToBytes(big.NewInt(-1))
	assert.Len(t, b, ScalarByteSize)
	for _, byt := range b {
		assert.Equal(t, byte(0xff), byt)
	}
}

func TestBigToBytesRoundTrip(t *testing.T) {
	// Encode then decode via SetBytes should reproduce the original value for
	// positive numbers.
	values := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(255),
		big.NewInt(256),
		new(big.Int).Lsh(big.NewInt(1), 200),
	}
	for _, v := range values {
		b := BigToBytes(v)
		assert.Len(t, b, ScalarByteSize)
		back := new(big.Int).SetBytes(b)
		assert.Zero(t, back.Cmp(v), "round-trip failed for %s", v)
	}
}

// ---------------------------------------------------------------------------
// BaseZr
// ---------------------------------------------------------------------------

// modulus used across all BaseZr tests.
var testModulus = func() big.Int {
	m, _ := new(big.Int).SetString(
		"73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
		16,
	)

	return *m
}()

func newZr(i int64) *BaseZr {
	return &BaseZr{Int: *big.NewInt(i), Modulus: testModulus}
}

func TestBaseZrIsZero(t *testing.T) {
	assert.True(t, newZr(0).IsZero())
	assert.False(t, newZr(1).IsZero())
	assert.False(t, newZr(-1).IsZero())
}

func TestBaseZrIsOne(t *testing.T) {
	assert.True(t, newZr(1).IsOne())
	assert.False(t, newZr(0).IsOne())
	assert.False(t, newZr(2).IsOne())
	assert.False(t, newZr(-1).IsOne())
}

func TestBaseZrBigInt(t *testing.T) {
	z := newZr(99)
	assert.Zero(t, z.BigInt().Cmp(big.NewInt(99)))
}

func TestBaseZrPlus(t *testing.T) {
	a := newZr(5)
	b := newZr(7)
	c := a.Plus(b).(*BaseZr)
	assert.Zero(t, c.Cmp(big.NewInt(12)))
}

func TestBaseZrMinus(t *testing.T) {
	a := newZr(10)
	b := newZr(3)
	c := a.Minus(b).(*BaseZr)
	assert.Zero(t, c.Cmp(big.NewInt(7)))
}

func TestBaseZrMul(t *testing.T) {
	a := newZr(6)
	b := newZr(7)
	c := a.Mul(b).(*BaseZr)
	assert.Zero(t, c.Cmp(big.NewInt(42)))
}

func TestBaseZrPowMod(t *testing.T) {
	// 2^10 mod p == 1024
	a := newZr(2)
	exp := newZr(10)
	r := a.PowMod(exp).(*BaseZr)
	assert.Zero(t, r.Cmp(big.NewInt(1024)))
}

func TestBaseZrMod(t *testing.T) {
	a := newZr(7)
	m := newZr(3)
	a.Mod(m)
	assert.Zero(t, a.Cmp(big.NewInt(1)))
}

func TestBaseZrInvModP(t *testing.T) {
	// 3 * 4 ≡ 1 (mod 11)
	a := newZr(3)
	p := newZr(11)
	a.InvModP(p)
	assert.Zero(t, a.Cmp(big.NewInt(4)))
}

func TestBaseZrInvModOrder(t *testing.T) {
	a := newZr(7)
	orig := new(big.Int).Set(&a.Int)
	a.InvModOrder()
	// a * a^-1 ≡ 1 (mod modulus)
	prod := new(big.Int).Mul(orig, &a.Int)
	prod.Mod(prod, &testModulus)
	assert.Zero(t, prod.Cmp(big.NewInt(1)))
}

func TestBaseZrBytesPositive(t *testing.T) {
	a := newZr(123)
	b := a.Bytes()
	assert.Len(t, b, ScalarByteSize)
	// Decode and compare
	back := new(big.Int).SetBytes(b)
	assert.Zero(t, back.Cmp(big.NewInt(123)))
}

func TestBaseZrBytesNegative(t *testing.T) {
	// A negative number is reduced mod p before encoding.
	a := &BaseZr{Int: *big.NewInt(-1), Modulus: testModulus}
	b := a.Bytes()
	assert.Len(t, b, ScalarByteSize)
	// The result should equal (p - 1).
	expected := new(big.Int).Sub(&testModulus, big.NewInt(1))
	back := new(big.Int).SetBytes(b)
	assert.Zero(t, back.Cmp(expected))
}

func TestBaseZrEquals(t *testing.T) {
	a := newZr(42)
	b := newZr(42)
	c := newZr(43)
	assert.True(t, a.Equals(b))
	assert.False(t, a.Equals(c))
}

func TestBaseZrCopy(t *testing.T) {
	a := newZr(55)
	b := a.Copy().(*BaseZr)
	assert.True(t, a.Equals(b))
	// Mutating the copy must not affect the original.
	b.Add(&b.Int, big.NewInt(1))
	assert.False(t, a.Equals(b))
}

func TestBaseZrClone(t *testing.T) {
	a := newZr(77)
	b := newZr(0)
	b.Clone(a)
	assert.True(t, a.Equals(b))
}

func TestBaseZrString(t *testing.T) {
	a := newZr(255)
	assert.Equal(t, "ff", a.String())
}

func TestBaseZrNeg(t *testing.T) {
	a := newZr(10)
	a.Neg()
	assert.Zero(t, a.Cmp(big.NewInt(-10)))
}

// ---------------------------------------------------------------------------
// CurveBase
// ---------------------------------------------------------------------------

func newCurveBase() *CurveBase {
	return &CurveBase{Modulus: testModulus}
}

func newCBZr(i int64) *BaseZr {
	cb := newCurveBase()

	return cb.NewZrFromInt64(i).(*BaseZr)
}

func TestCurveBaseGroupOrder(t *testing.T) {
	cb := newCurveBase()
	order := cb.GroupOrder().(*BaseZr)
	assert.Zero(t, order.Cmp(&testModulus))
}

func TestCurveBaseNewZrFromBytes(t *testing.T) {
	cb := newCurveBase()
	b := BigToBytes(big.NewInt(9999))
	z := cb.NewZrFromBytes(b).(*BaseZr)
	assert.Zero(t, z.Cmp(big.NewInt(9999)))
}

func TestCurveBaseNewZrFromInt64(t *testing.T) {
	cb := newCurveBase()
	z := cb.NewZrFromInt64(12345).(*BaseZr)
	assert.Zero(t, z.Cmp(big.NewInt(12345)))
}

func TestCurveBaseNewZrFromUint64(t *testing.T) {
	cb := newCurveBase()
	z := cb.NewZrFromUint64(99999).(*BaseZr)
	assert.Zero(t, z.Cmp(new(big.Int).SetUint64(99999)))
}

func TestCurveBaseNewZrFromBigInt(t *testing.T) {
	cb := newCurveBase()
	n := big.NewInt(77777)
	z := cb.NewZrFromBigInt(n).(*BaseZr)
	assert.Zero(t, z.Cmp(n))
}

func TestCurveBaseNewRandomZr(t *testing.T) {
	cb := newCurveBase()
	rng, err := cb.Rand()
	require.NoError(t, err)
	r := cb.NewRandomZr(rng).(*BaseZr)
	// Must be in [0, modulus)
	assert.GreaterOrEqual(t, r.Sign(), 0)
	assert.Negative(t, r.Cmp(&testModulus))
}

func TestCurveBaseHashToZr(t *testing.T) {
	cb := newCurveBase()
	h := cb.HashToZr([]byte("hello")).(*BaseZr)
	assert.GreaterOrEqual(t, h.Sign(), 0)
	assert.Negative(t, h.Cmp(&testModulus))
}

func TestCurveBaseModNeg(t *testing.T) {
	cb := newCurveBase()
	m := newCBZr(11)
	a := newCBZr(3)
	neg := cb.ModNeg(a, m).(*BaseZr)
	// a + (-a) ≡ 0 (mod m)
	sum := new(big.Int).Add(&a.Int, &neg.Int)
	sum.Mod(sum, big.NewInt(11))
	assert.Zero(t, sum.Cmp(big.NewInt(0)))
}

func TestCurveBaseModSub(t *testing.T) {
	cb := newCurveBase()
	m := newCBZr(11)
	a := newCBZr(8)
	b := newCBZr(3)
	r := cb.ModSub(a, b, m).(*BaseZr)
	assert.Zero(t, r.Cmp(big.NewInt(5)))
}

func TestCurveBaseModAdd(t *testing.T) {
	cb := newCurveBase()
	m := newCBZr(11)
	a := newCBZr(8)
	b := newCBZr(6)
	r := cb.ModAdd(a, b, m).(*BaseZr)
	assert.Zero(t, r.Cmp(big.NewInt(3))) // (8+6) mod 11 = 3
}

func TestCurveBaseModMul(t *testing.T) {
	cb := newCurveBase()
	m := newCBZr(11)
	a := newCBZr(4)
	b := newCBZr(5)
	r := cb.ModMul(a, b, m).(*BaseZr)
	assert.Zero(t, r.Cmp(big.NewInt(9))) // 20 mod 11 = 9
}

func TestCurveBaseModAddMul(t *testing.T) {
	cb := newCurveBase()
	m := newCBZr(100)
	a1 := newCBZr(3)
	b1 := newCBZr(4)
	a2 := newCBZr(5)
	b2 := newCBZr(6)
	// (3*4) + (5*6) = 12 + 30 = 42
	r := cb.ModAddMul(
		[]driver.Zr{a1, a2},
		[]driver.Zr{b1, b2},
		m,
	)
	assert.Zero(t, r.(*BaseZr).Cmp(big.NewInt(42)))
}

func TestCurveBaseModAddMul2(t *testing.T) {
	cb := newCurveBase()
	m := newCBZr(100)
	a1 := newCBZr(3)
	c1 := newCBZr(4)
	b1 := newCBZr(5)
	c2 := newCBZr(6)
	// (3*4) + (5*6) = 42
	r := cb.ModAddMul2(a1, c1, b1, c2, m).(*BaseZr)
	assert.Zero(t, r.Cmp(big.NewInt(42)))
}

func TestCurveBaseModAddMul3(t *testing.T) {
	cb := newCurveBase()
	m := newCBZr(1000)
	a1 := newCBZr(2)
	a2 := newCBZr(3)
	b1 := newCBZr(4)
	b2 := newCBZr(5)
	c1 := newCBZr(6)
	c2 := newCBZr(7)
	// (2*3) + (4*5) + (6*7) = 6 + 20 + 42 = 68
	r := cb.ModAddMul3(a1, a2, b1, b2, c1, c2, m).(*BaseZr)
	assert.Zero(t, r.Cmp(big.NewInt(68)))
}

func TestCurveBaseModMulInPlace(t *testing.T) {
	cb := newCurveBase()
	m := newCBZr(100)
	result := newCBZr(0)
	a := newCBZr(6)
	b := newCBZr(7)
	cb.ModMulInPlace(result, a, b, m)
	assert.Zero(t, result.Cmp(big.NewInt(42)))
}

func TestCurveBaseModAddMul2InPlace(t *testing.T) {
	cb := newCurveBase()
	m := newCBZr(100)
	result := newCBZr(0)
	a1 := newCBZr(3)
	c1 := newCBZr(4)
	b1 := newCBZr(5)
	c2 := newCBZr(6)
	cb.ModAddMul2InPlace(result, a1, c1, b1, c2, m)
	assert.Zero(t, result.Cmp(big.NewInt(42)))
}

func TestCurveBaseModAddMul3InPlace(t *testing.T) {
	cb := newCurveBase()
	m := newCBZr(1000)
	result := newCBZr(0)
	a1 := newCBZr(2)
	a2 := newCBZr(3)
	b1 := newCBZr(4)
	b2 := newCBZr(5)
	c1 := newCBZr(6)
	c2 := newCBZr(7)
	cb.ModAddMul3InPlace(result, a1, a2, b1, b2, c1, c2, m)
	assert.Zero(t, result.Cmp(big.NewInt(68)))
}
