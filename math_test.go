/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package math

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var seed = time.Now().Unix()

func runZrTest(t *testing.T, c *Curve) {
	assert.True(t, c.NewZrFromInt(35).Plus(c.NewZrFromInt(1)).Equals(c.NewZrFromInt(36)))
	assert.True(t, c.NewZrFromInt(36).Copy().Equals(c.NewZrFromInt(36)))
	i := c.NewZrFromInt(5)
	i.Mod(c.NewZrFromInt(3))
	assert.True(t, i.Equals(c.NewZrFromInt(2)))
	i = c.NewZrFromInt(3)
	i.InvModP(c.NewZrFromInt(11))
	assert.True(t, i.Equals(c.NewZrFromInt(4)))
	assert.Equal(t, c.NewZrFromInt(35).String(), "23")

	rand.Seed(seed)

	i64 := rand.Int63()
	i = c.NewZrFromInt(i64)
	i64_, err := i.Int()
	assert.NoError(t, err)
	assert.Equal(t, i64, i64_)

	i64 = 0 - i64
	i = c.NewZrFromInt(i64)
	i64_, err = i.Int()
	assert.NoError(t, err)
	assert.Equal(t, i64, i64_)

	i = c.NewZrFromInt(math.MaxInt64)
	i = i.Plus(c.NewZrFromInt(math.MaxInt64))
	i = i.Plus(c.NewZrFromInt(2))
	_, err = i.Int()
	assert.EqualError(t, err, "out of range")

	// D/H
	rng, err := c.Rand()
	assert.NoError(t, err)
	r1 := c.NewRandomZr(rng)
	r2 := c.NewRandomZr(rng)
	r3 := c.NewRandomZr(rng)
	a1 := r1.PowMod(r2).PowMod(r3)
	a2 := r1.PowMod(r3).PowMod(r2)
	assert.True(t, a1.Equals(a2))

	// Euler's totient
	assert.True(t, r1.PowMod(c.GroupOrder.Plus(c.NewZrFromInt(-1))).Equals(c.NewZrFromInt(1)), fmt.Sprintf("failed with curve %T", c.c))
}

func runG1Test(t *testing.T, c *Curve) {
	assert.Equal(t, "(1,2)", c.GenG1.String())

	g1copy := c.NewG1()
	g1copy.Clone(c.GenG1)
	assert.True(t, c.GenG1.Equals(g1copy))

	g1 := c.GenG1.Mul(c.NewZrFromInt(35))
	g2 := c.GenG1.Mul(c.NewZrFromInt(23))
	g3 := c.GenG1.Mul(c.NewZrFromInt(58))

	g1.Add(g2)
	assert.True(t, g1.Equals(g3))
	assert.True(t, g2.Equals(c.GenG1.Mul(c.NewZrFromInt(23))))

	assert.True(t, c.GenG1.Mul(c.NewZrFromInt(58)).Equals(c.GenG1.Mul2(c.NewZrFromInt(35), c.GenG1, c.NewZrFromInt(23))))

	g4 := c.GenG1.Mul(c.NewZrFromInt(35))
	g5 := c.GenG1.Mul(c.NewZrFromInt(23))
	g6 := c.GenG1.Mul(c.NewZrFromInt(58))

	g6.Sub(g5)
	assert.True(t, g6.Equals(g4))
	assert.True(t, g5.Equals(c.GenG1.Mul(c.NewZrFromInt(23))))

	assert.False(t, g6.IsInfinity())

	g1copy = c.NewG1()
	g1copy.Clone(c.GenG1)
	g1copy.Sub(c.GenG1)
	assert.True(t, g1copy.IsInfinity())

	assert.False(t, c.HashToG1([]byte("Amazing Grace (how sweet the sound)")).IsInfinity())
}

func runG2Test(t *testing.T, c *Curve) {
	g2copy := c.NewG2()
	g2copy.Clone(c.GenG2)
	assert.True(t, c.GenG2.Equals(g2copy))

	g1 := c.GenG2.Mul(c.NewZrFromInt(35))
	g2 := c.GenG2.Mul(c.NewZrFromInt(23))
	g3 := c.GenG2.Mul(c.NewZrFromInt(58))
	g1.Add(g2)
	assert.True(t, g1.Equals(g3))
	assert.True(t, g2.Equals(c.GenG2.Mul(c.NewZrFromInt(23))))
	g1.Sub(g2)
	assert.True(t, g1.Equals(c.GenG2.Mul(c.NewZrFromInt(35))), fmt.Sprintf("failed with curve %T", c.c))

	g4 := c.GenG2.Mul(c.NewZrFromInt(35))
	g5 := c.GenG2.Mul(c.NewZrFromInt(23))
	g6 := c.GenG2.Mul(c.NewZrFromInt(58))
	g4.Affine()
	g5.Affine()
	g6.Affine()
	g4.Add(g5)
	assert.True(t, g4.Equals(g6))
	assert.True(t, g5.Equals(c.GenG2.Mul(c.NewZrFromInt(23))))
}

func runPowTest(t *testing.T, c *Curve) {
	rand.Seed(time.Now().Unix())

	a := big.NewInt(int64(rand.Int31()))
	b := big.NewInt(int64(rand.Int31()))
	ab := big.NewInt(0).Mul(a, b)

	x := c.NewZrFromInt(a.Int64())
	y := c.NewZrFromInt(b.Int64())
	xy := c.NewZrFromInt(ab.Int64())

	g1x := c.GenG1.Mul(x)
	g2y := c.GenG2.Mul(y)
	expected := c.Pairing(g2y, g1x)
	expected = c.FExp(expected)

	actual := c.Pairing(c.GenG2, c.GenG1)
	actual = c.FExp(actual)
	actual.Exp(xy)

	assert.True(t, expected.Equals(actual))
}

func runPairingTest(t *testing.T, c *Curve) {
	r0 := c.NewZrFromInt(1541)
	g1r := c.GenG1.Mul(r0)
	g2r := c.GenG2.Mul(r0)
	a := c.Pairing(g2r, c.GenG1)
	b := c.Pairing(c.GenG2, g1r)
	a = c.FExp(a)
	b = c.FExp(b)
	assert.True(t, a.Equals(b))

	rng, err := c.Rand()
	assert.NoError(t, err)
	r1 := c.NewRandomZr(rng)
	r2 := c.NewRandomZr(rng)
	r3 := c.NewRandomZr(rng)
	r4 := c.NewRandomZr(rng)
	p := c.GenG2.Mul(r1)
	q := c.GenG1.Mul(r2)
	r := c.GenG2.Mul(r3)
	s := c.GenG1.Mul(r4)
	tt1 := c.Pairing2(p, q, r, s)
	tt1 = c.FExp(tt1)

	tt2 := c.Pairing(c.GenG2.Mul(r1).Mul(r2), c.GenG1)
	tt2 = c.FExp(tt2)
	tt3 := c.Pairing(c.GenG2, c.GenG1.Mul(r3).Mul(r4))
	tt3 = c.FExp(tt3)

	tt2.Mul(tt3)

	assert.True(t, tt1.Equals(tt2))
}

func runGtTest(t *testing.T, c *Curve) {
	r := c.NewZrFromInt(1541)
	g2r := c.GenG2.Mul(r)
	a := c.Pairing(g2r, c.GenG1)
	ainv := c.Pairing(g2r, c.GenG1)
	ainv.Inverse()
	ainv.Mul(a)
	assert.True(t, ainv.IsUnity())

	gengt := c.Pairing(c.GenG2, c.GenG1)
	gengt = c.FExp(gengt)
	assert.True(t, gengt.Equals(c.GenGt))
}

func runRndTest(t *testing.T, c *Curve) {
	rng, err := c.Rand()
	assert.NoError(t, err)
	r := c.NewRandomZr(rng)
	gr := c.GenG1.Mul(r)

	r.InvModP(c.GroupOrder)
	one := gr.Mul(r)
	assert.True(t, c.GenG1.Equals(one))
}

func runHashTest(t *testing.T, c *Curve) {
	bytes := make([]byte, 128)
	rand.Read(bytes)

	r := c.HashToZr(bytes)
	gr := c.GenG1.Mul(r)

	r.InvModP(c.GroupOrder)
	one := gr.Mul(r)
	assert.True(t, c.GenG1.Equals(one))
}

func runToFroBytesTest(t *testing.T, c *Curve) {
	rng, err := c.Rand()
	assert.NoError(t, err)
	r := c.NewRandomZr(rng)
	rbytes := r.Bytes()
	rback := c.NewZrFromBytes(rbytes)
	assert.NoError(t, err)
	assert.True(t, r.Equals(rback))

	g1r := c.GenG1.Mul(r)
	g1rbytes := g1r.Bytes()
	g1rback, err := c.NewG1FromBytes(g1rbytes)
	assert.NoError(t, err)
	assert.True(t, g1r.Equals(g1rback))

	g2r := c.GenG2.Mul(r)
	g2rbytes := g2r.Bytes()
	g2rback, err := c.NewG2FromBytes(g2rbytes)
	assert.NoError(t, err)
	assert.True(t, g2r.Equals(g2rback))

	g2r = c.GenG2.Mul(r)
	a := c.Pairing(g2r, c.GenG1)
	abytes := a.Bytes()
	aback, err := c.NewGtFromBytes(abytes)
	assert.NoError(t, err)
	assert.True(t, a.Equals(aback))

	g1rback, err = c.NewG1FromBytes(nil)
	assert.Nil(t, g1rback)
	assert.Error(t, err)

	g2rback, err = c.NewG2FromBytes(nil)
	assert.Nil(t, g2rback)
	assert.Error(t, err)

	gtrback, err := c.NewGtFromBytes(nil)
	assert.Nil(t, gtrback)
	assert.Error(t, err)
}

func runModAddSubNegTest(t *testing.T, c *Curve) {
	rng, err := c.Rand()
	assert.NoError(t, err)
	r := c.NewRandomZr(rng)

	minusr := c.ModNeg(r, c.GroupOrder)
	assert.True(t, c.ModAdd(r, minusr, c.GroupOrder).Equals(c.NewZrFromInt(0)))

	a := c.NewRandomZr(rng)
	b := c.NewRandomZr(rng)
	apb := c.ModAdd(a, b, c.GroupOrder)
	bagain := c.ModSub(apb, a, c.GroupOrder)
	assert.True(t, bagain.Equals(b))
}

func runDHTestG1(t *testing.T, c *Curve) {
	rng, err := c.Rand()
	assert.NoError(t, err)
	a := c.NewRandomZr(rng)
	b := c.NewRandomZr(rng)

	ga := c.GenG1.Mul(a)
	gb := c.GenG1.Mul(b)
	gab := ga.Mul(b)
	gba := gb.Mul(a)
	assert.True(t, gab.Equals(gba))

	ab := c.ModMul(a, b, c.GroupOrder)
	gab1 := c.GenG1.Mul(ab)
	assert.True(t, gab.Equals(gab1))
}

func runDHTestG2(t *testing.T, c *Curve) {
	rng, err := c.Rand()
	assert.NoError(t, err)
	a := c.NewRandomZr(rng)
	b := c.NewRandomZr(rng)

	ga := c.GenG2.Mul(a)
	gb := c.GenG2.Mul(b)
	gab := ga.Mul(b)
	gba := gb.Mul(a)
	assert.True(t, gab.Equals(gba))

	ab := c.ModMul(a, b, c.GroupOrder)
	gab1 := c.GenG2.Mul(ab)
	assert.True(t, gab.Equals(gab1))
}

func runCopyCloneTest(t *testing.T, c *Curve) {
	rng, err := c.Rand()
	assert.NoError(t, err)

	a := c.NewRandomZr(rng)
	aclone := c.NewRandomZr(rng)
	aclone.Clone(a)
	assert.True(t, a.Equals(aclone))
	acopy := aclone.Copy()
	assert.True(t, acopy.Equals(aclone))

	g1 := c.GenG1.Mul(a)
	g1clone := c.NewG1()
	g1clone.Clone(g1)
	assert.True(t, g1.Equals(g1clone))
	g1copy := g1clone.Copy()
	assert.True(t, g1copy.Equals(g1clone))

	g2 := c.GenG2.Mul(a)
	g2clone := c.NewG2()
	g2clone.Clone(g2)
	assert.True(t, g2.Equals(g2clone))
	g2copy := g2clone.Copy()
	assert.True(t, g2copy.Equals(g2clone))
}

func testModAdd(t *testing.T, c *Curve) {
	i1 := c.NewZrFromInt(math.MaxInt64)
	i2 := c.NewZrFromInt(math.MaxInt64)
	g1 := c.GenG1.Mul2(i1, c.GenG1, i2)

	i3 := c.ModAdd(i1, i2, c.GroupOrder)
	g2 := c.GenG1.Mul(i3)

	assert.True(t, g1.Equals(g2), fmt.Sprintf("failed with curve %T", c.c))
}

func testNotZeroAfterAdd(t *testing.T, c *Curve) {
	i1 := c.NewZrFromInt(math.MaxInt64)
	i2 := c.NewZrFromInt(math.MaxInt64)
	i3 := c.NewZrFromInt(2)

	i4 := i1.Plus(i2).Plus(i3)

	zero := c.NewZrFromInt(0)

	assert.False(t, zero.Equals(i4), fmt.Sprintf("failed with curve %T", c.c))
}

type testJsonStruct struct {
	Zr *Zr
	G1 *G1
	G2 *G2
	Gt *Gt
}

func runJsonMarshaler(t *testing.T, c *Curve) {
	rng, err := c.Rand()
	assert.NoError(t, err)

	zr := c.NewRandomZr(rng)
	g1 := c.GenG1.Mul(zr)
	g2 := c.GenG2.Mul(zr)
	gt := c.Pairing(g2, g1)

	testStruct := &testJsonStruct{
		Zr: zr,
		G1: g1,
		G2: g2,
		Gt: gt,
	}

	bytes, err := json.Marshal(testStruct)
	assert.NoError(t, err)

	testStruct = &testJsonStruct{}
	err = json.Unmarshal(bytes, testStruct)
	assert.NoError(t, err)

	assert.True(t, testStruct.Zr.Equals(zr), fmt.Sprintf("failed with curve %T", c.c))
	assert.True(t, testStruct.G1.Equals(g1), fmt.Sprintf("failed with curve %T", c.c))
	assert.True(t, testStruct.G2.Equals(g2), fmt.Sprintf("failed with curve %T", c.c))
	assert.True(t, testStruct.Gt.Equals(gt), fmt.Sprintf("failed with curve %T", c.c))
}

func TestJSONMarshalerFails(t *testing.T) {
	var err error
	zr, g1, g2, gt := &Zr{}, &G1{}, &G2{}, &Gt{}

	err = json.Unmarshal([]byte(`{"element":1}`), zr)
	assert.EqualError(t, err, "json: cannot unmarshal number into Go struct field curveElement.element of type []uint8")

	err = json.Unmarshal([]byte(`{"element":1}`), g1)
	assert.EqualError(t, err, "json: cannot unmarshal number into Go struct field curveElement.element of type []uint8")

	err = json.Unmarshal([]byte(`{"element":1}`), g2)
	assert.EqualError(t, err, "json: cannot unmarshal number into Go struct field curveElement.element of type []uint8")

	err = json.Unmarshal([]byte(`{"element":1}`), gt)
	assert.EqualError(t, err, "json: cannot unmarshal number into Go struct field curveElement.element of type []uint8")

	// err = json.Unmarshal([]byte(`{"element":"YQo="}`), zr)
	// assert.EqualError(t, err, "json: cannot unmarshal number into Go struct field curveElement.element of type []uint8")

	err = json.Unmarshal([]byte(`{"element":"YQo="}`), g1)
	assert.EqualError(t, err, "failure [runtime error: index out of range [2] with length 2]")

	err = json.Unmarshal([]byte(`{"element":"YQo="}`), g2)
	assert.EqualError(t, err, "failure [runtime error: index out of range [2] with length 2]")

	err = json.Unmarshal([]byte(`{"element":"YQo="}`), gt)
	assert.EqualError(t, err, "failure [runtime error: index out of range [2] with length 2]")
}

func TestCurves(t *testing.T) {
	for _, curve := range Curves {
		testNotZeroAfterAdd(t, curve)
		testModAdd(t, curve)
		runZrTest(t, curve)
		runG1Test(t, curve)
		runG2Test(t, curve)
		runPairingTest(t, curve)
		runGtTest(t, curve)
		runRndTest(t, curve)
		runHashTest(t, curve)
		runToFroBytesTest(t, curve)
		runModAddSubNegTest(t, curve)
		runDHTestG1(t, curve)
		runDHTestG2(t, curve)
		runCopyCloneTest(t, curve)
		runJsonMarshaler(t, curve)
		runPowTest(t, curve)
	}
}
