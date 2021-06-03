/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package math

import (
	"encoding/json"
	"fmt"
	"math"
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
	}
}

func TestG1_Bytes(t *testing.T) {
	BN256 := Curves[BN256]
	FP256BN := Curves[FP256BN_AMCL]

	assert.Equal(t, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2}, BN256.GenG1.Bytes())
	assert.Equal(t, []byte{0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2}, FP256BN.GenG1.Bytes())
}

func TestG2_Bytes(t *testing.T) {
	BN256 := Curves[BN256]
	FP256BN := Curves[FP256BN_AMCL]

	assert.Equal(t, []byte{0x19, 0x8e, 0x93, 0x93, 0x92, 0xd, 0x48, 0x3a, 0x72, 0x60, 0xbf, 0xb7, 0x31, 0xfb, 0x5d, 0x25, 0xf1, 0xaa, 0x49, 0x33, 0x35, 0xa9, 0xe7, 0x12, 0x97, 0xe4, 0x85, 0xb7, 0xae, 0xf3, 0x12, 0xc2, 0x18, 0x0, 0xde, 0xef, 0x12, 0x1f, 0x1e, 0x76, 0x42, 0x6a, 0x0, 0x66, 0x5e, 0x5c, 0x44, 0x79, 0x67, 0x43, 0x22, 0xd4, 0xf7, 0x5e, 0xda, 0xdd, 0x46, 0xde, 0xbd, 0x5c, 0xd9, 0x92, 0xf6, 0xed, 0x9, 0x6, 0x89, 0xd0, 0x58, 0x5f, 0xf0, 0x75, 0xec, 0x9e, 0x99, 0xad, 0x69, 0xc, 0x33, 0x95, 0xbc, 0x4b, 0x31, 0x33, 0x70, 0xb3, 0x8e, 0xf3, 0x55, 0xac, 0xda, 0xdc, 0xd1, 0x22, 0x97, 0x5b, 0x12, 0xc8, 0x5e, 0xa5, 0xdb, 0x8c, 0x6d, 0xeb, 0x4a, 0xab, 0x71, 0x80, 0x8d, 0xcb, 0x40, 0x8f, 0xe3, 0xd1, 0xe7, 0x69, 0xc, 0x43, 0xd3, 0x7b, 0x4c, 0xe6, 0xcc, 0x1, 0x66, 0xfa, 0x7d, 0xaa}, BN256.GenG2.Bytes())
	assert.Equal(t, []byte{0xfe, 0xc, 0x33, 0x50, 0xb4, 0xc9, 0x6c, 0x20, 0x28, 0x56, 0xf, 0x57, 0x7c, 0x28, 0x91, 0x3a, 0xce, 0x1c, 0x53, 0x9a, 0x12, 0xbf, 0x84, 0x3c, 0xd2, 0x26, 0x16, 0xb6, 0x89, 0xc0, 0x9e, 0xfb, 0x4e, 0xa6, 0x60, 0x57, 0x73, 0x8a, 0xc0, 0x54, 0xdb, 0x5a, 0xe1, 0xc6, 0x37, 0xd8, 0x13, 0xb9, 0x24, 0xdd, 0x78, 0xe2, 0x87, 0xd0, 0x35, 0x89, 0xd2, 0x69, 0xed, 0x34, 0xa3, 0x7e, 0x6a, 0x2b, 0x70, 0x20, 0x46, 0xe7, 0xc5, 0x42, 0xa3, 0xb3, 0x76, 0x77, 0xd, 0x75, 0x12, 0x4e, 0x3e, 0x51, 0xef, 0xcb, 0x24, 0x75, 0x8d, 0x61, 0x58, 0x48, 0xe9, 0x9, 0xb4, 0x81, 0xbe, 0xdc, 0x27, 0xff, 0x5, 0x54, 0xe3, 0xbc, 0xd3, 0x88, 0xc2, 0x90, 0x42, 0xee, 0xa6, 0x49, 0x29, 0x7e, 0xb2, 0x9f, 0x8b, 0x4c, 0xbe, 0x80, 0x82, 0x1a, 0x98, 0xb3, 0xe0, 0x12, 0x81, 0x11, 0x4a, 0xad, 0x4, 0x9b}, FP256BN.GenG2.Bytes())

	assert.Equal(t, "E([10857046999023057135944570762232829481370756359578518086990519993285655852781+11559732032986387107991004021392285783925812861821192530917403151452391805634*u,8495653923123431417604973247489272438418190587263600148770280649306958101930+4082367875863433681332203403145435568316851327593401208105741076214120093531*u]),", BN256.GenG2.String())
	assert.Equal(t, "([fe0c3350b4c96c2028560f577c28913ace1c539a12bf843cd22616b689c09efb,4ea66057738ac054db5ae1c637d813b924dd78e287d03589d269ed34a37e6a2b],[702046e7c542a3b376770d75124e3e51efcb24758d615848e909b481bedc27ff,0554e3bcd388c29042eea649297eb29f8b4cbe80821a98b3e01281114aad049b])", FP256BN.GenG2.String())
}

func TestGt_String(t *testing.T) {
	BN256 := Curves[BN256]
	FP256BN := Curves[FP256BN_AMCL]

	assert.Equal(t, "8493334370784016972005089913588211327688223499729897951716206968320726508021+3758435817766288188804561253838670030762970764366672594784247447067868088068*u+(6565798094314091391201231504228224566495939541538094766881371862976727043038+14656606573936501743457633041048024656612227301473084805627390748872617280984*u)*v+(634997487638609332803583491743335852620873788902390365055086820718589720118+19455424343576886430889849773367397946457449073528455097210946839000147698372*u)*v**2+(20049218015652006197026173611347504489508678646783216776320737476707192559881+18059168546148152671857026372711724379319778306792011146784665080987064164612*u+(12145052038566888241256672223106590273978429515702193755778990643425246950730+17918828665069491344039743589118342552553375221610735811112289083834142789347*u)*v+(6223602427219597392892794664899549544171383137467762280768257680446283161705+7484542354754424633621663080190936924481536615300815203692506276894207018007*u)*v**2)*w", BN256.GenGt.String())
	assert.Equal(t, "[[[dcad9925265ba3485fd0cd71b7cc0a7c92dda96c9a509e0299db97361f7274a0,17b55ca56574aea9065ffe63dfba741bb62992fe6c4a146711bb0ca0f01bffd0],[223b69f4df921d748ccf9c281993ba83aea5a0475264c955c6bf6d57612b9981,9bcbe86bb637eade05544dce875bf6e35d2bec22324aa8a80de852ee9fe05d77]],[[dcd92c43d63d9f8acceabe292f7fe35cf250cff0dbb1db68cbc225bf94ab28d7,c3cc816536663e4940511e04d0eaa95fa3076e374b03e944b757bde644b4cdd6],[9c90253e8c3b3ab7aafaa39c7b96f7c483e63004c18acbce83ae8d77d493151f,09ce0d960efe73c650a2cce3ce56a149cacd04248fe021b1b696e922a76eb960]],[[7600f33a19cd9e2232ee44715d5c8ced17acbcb70899286bc69c9520a9060c41,d5055d58eb0958e353eec92c9b09a4bdba1e9b7df09a2ab57414663e01844a64],[d11bb134f77f807476ba028ef2b74d20cb52122ed0838646d908e69b5701d02d,8899ca9a093c3b30dc46254a14eb343a330c0281b94f721877b53b27716c5dc8]]]", FP256BN.GenGt.String())
}

func TestZr_Bytes(t *testing.T) {
	BN256 := Curves[BN256]
	FP256BN := Curves[FP256BN_AMCL]

	assert.Equal(t, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x23}, BN256.NewZrFromInt(35).Bytes())
	assert.Equal(t, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x23}, FP256BN.NewZrFromInt(35).Bytes())
}
