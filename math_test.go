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
	rng, err := c.Rand()
	assert.NoError(t, err)

	// serialising and deserialising negative numbers
	rr := c.NewRandomZr(rng)
	rr1 := rr.Copy()
	rr1.Neg()
	rr1b := rr1.Bytes()
	rr11 := c.NewZrFromBytes(rr1b)
	res := c.ModAdd(rr, rr11, c.GroupOrder)
	assert.True(t, res.Equals(c.NewZrFromInt(0)), fmt.Sprintf("failed with curve %T", c.c))

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

	i1 := c.NewZrFromInt(i64)
	i64 = 0 - i64
	i2 := c.NewZrFromInt(i64)
	i3 := i1.Plus(i2)
	i3.Mod(c.GroupOrder)
	assert.True(t, i3.Equals(c.NewZrFromInt(0)))
	i = c.NewZrFromInt(math.MaxInt64)
	i = i.Plus(c.NewZrFromInt(math.MaxInt64))
	i = i.Plus(c.NewZrFromInt(2))
	_, err = i.Int()
	assert.EqualError(t, err, "out of range")

	// D/H
	r1 := c.NewRandomZr(rng)
	r2 := c.NewRandomZr(rng)
	r3 := c.NewRandomZr(rng)
	a1 := r1.PowMod(r2).PowMod(r3)
	a2 := r1.PowMod(r3).PowMod(r2)
	assert.True(t, a1.Equals(a2))

	// large negative numbers
	i1 = c.NewRandomZr(rng)
	i2 = i1.Copy()
	i2 = c.ModNeg(i2, c.GroupOrder)
	i3 = i1.Plus(i2)
	i3.Mod(c.GroupOrder)
	assert.True(t, i3.Equals(c.NewZrFromInt(0)), fmt.Sprintf("failed with curve %T", c.c))

	// large negative numbers with neg
	i1 = c.NewRandomZr(rng)
	i2 = i1.Copy()
	i2.Neg()
	i3 = i1.Plus(i2)
	i3.Mod(c.GroupOrder)
	assert.True(t, i3.Equals(c.NewZrFromInt(0)), fmt.Sprintf("failed with curve %T", c.c))

	// large negative numbers with minus
	i1 = c.NewRandomZr(rng)
	i2 = i1.Copy()
	i3 = i1.Minus(i2)
	i3.Mod(c.GroupOrder)
	assert.True(t, i3.Equals(c.NewZrFromInt(0)), fmt.Sprintf("failed with curve %T", c.c))

	// Euler's totient
	assert.True(t, r1.PowMod(c.GroupOrder.Plus(c.NewZrFromInt(-1))).Equals(c.NewZrFromInt(1)), fmt.Sprintf("failed with curve %T", c.c))

	// byte size
	assert.Len(t, r1.Bytes(), c.ScalarByteSize)
}

var expectedG1Gens = []string{
	"(1,2)", // FP256BN_AMCL
	"(1,2)", // BN254 - in which case 1,2 isn't really the right representation
	"(1,2)", // FP256BN_AMCL_MIRACL
	"(3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507,1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569)", // BLS12_381
	"(81937999373150964239938255573465948239988671502647976594219695644855304257327692006745978603320413799295628339695,241266749859715473739788878240585681733927191168601896383759122102112907357779751001206799952863815012735208165030)",    // BLS12_377
	"(3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507,1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569)", // BLS12_381
	"(3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507,1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569)", // BLS12_381_BBS
	"(3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507,1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569)", // BLS12_381_BBS_GURVY
}

var expectedModuli = []string{
	"fffffffffffcf0cd46e5f25eee71a49e0cdc65fb1299921af62d536cd10b500d",
	"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
	"fffffffffffcf0cd46e5f25eee71a49e0cdc65fb1299921af62d536cd10b500d",
	"73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
	"12ab655e9a2ca55660b44d1e5c37b00159aa76fed00000010a11800000000001",
	"73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
	"73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
	"73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
}

func runG1Test(t *testing.T, c *Curve) {
	assert.Equal(t, expectedG1Gens[c.curveID], c.GenG1.String())

	assert.Equal(t, expectedModuli[c.curveID], c.GroupOrder.String(), fmt.Sprintf("failed with curve %T", c.c))

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

	GS := c.HashToG1([]byte("Amazing Grace (how sweet the sound)"))
	assert.False(t, GS.IsInfinity())
	assert.Len(t, GS.Bytes(), c.G1ByteSize)

	GS = c.HashToG1WithDomain([]byte("it's a heavy metal universe"), []byte("powerplant"))
	assert.False(t, GS.IsInfinity())
	assert.Len(t, GS.Bytes(), c.G1ByteSize)

	GS1 := GS.Copy()
	GS1.Neg()
	GS1.Add(GS)
	assert.True(t, GS1.IsInfinity())
	GS1.Add(c.GenG1)
	assert.True(t, GS1.Equals(c.GenG1))
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

	rng, err := c.Rand()
	assert.NoError(t, err)

	a := c.NewRandomZr(rng)
	p := c.GenG2.Mul(a)
	assert.Len(t, p.Bytes(), c.G2ByteSize)
	assert.Len(t, p.Compressed(), c.CompressedG2ByteSize)
}

func runPowTest(t *testing.T, c *Curve) {
	rng, err := c.Rand()
	assert.NoError(t, err)

	a := c.NewRandomZr(rng)
	b := c.NewRandomZr(rng)
	ab := a.Mul(b)

	gta := c.GenGt.Exp(a)
	gtb := c.GenGt.Exp(b)
	gtab := gta.Exp(b)
	gtba := gtb.Exp(a)

	assert.True(t, gtab.Equals(gtba))

	g1a := c.GenG1.Mul(a)
	g2b := c.GenG2.Mul(b)
	gt := c.Pairing(g2b, g1a)
	gt = c.FExp(gt)
	gt1 := c.Pairing(c.GenG2, c.GenG1)
	gt1 = c.FExp(gt1)
	gt1 = gt1.Exp(a)
	gt1 = gt1.Exp(b)

	assert.True(t, gt.Equals(gt1))

	gtab = c.Pairing(c.GenG2, c.GenG1)
	gtab = c.FExp(gtab)
	gtab = gtab.Exp(ab)
	assert.True(t, gtab.Equals(gt))
}

func runPairingTest(t *testing.T, c *Curve) {
	rng, err := c.Rand()
	assert.NoError(t, err)
	r0 := c.NewRandomZr(rng)
	g1r := c.GenG1.Mul(r0)
	g2r := c.GenG2.Mul(r0)
	a := c.Pairing(g2r, c.GenG1)
	b := c.Pairing(c.GenG2, g1r)
	a = c.FExp(a)
	b = c.FExp(b)
	assert.True(t, a.Equals(b))

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
	assert.Len(t, g1rbytes, c.G1ByteSize)
	g1rback, err := c.NewG1FromBytes(g1rbytes)
	assert.NoError(t, err)
	assert.True(t, g1r.Equals(g1rback))
	assert.Len(t, g1rback.Bytes(), c.G1ByteSize, fmt.Sprintf("failed with curve %T", c.c))
	assert.Len(t, g1rback.Compressed(), c.CompressedG1ByteSize, fmt.Sprintf("failed with curve %T", c.c))

	g2r := c.GenG2.Mul(r)
	g2rbytes := g2r.Bytes()
	assert.Len(t, g2rbytes, c.G2ByteSize)
	g2rback, err := c.NewG2FromBytes(g2rbytes)
	assert.NoError(t, err)
	assert.True(t, g2r.Equals(g2rback))
	assert.Len(t, g2rback.Bytes(), c.G2ByteSize, fmt.Sprintf("failed with curve %T", c.c))
	assert.Len(t, g2rback.Compressed(), c.CompressedG2ByteSize, fmt.Sprintf("failed with curve %T", c.c))

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

func runToFroCompressedTest(t *testing.T, c *Curve) {
	rng, err := c.Rand()
	assert.NoError(t, err)
	r := c.NewRandomZr(rng)

	g1r := c.GenG1.Mul(r)
	g1rbytes := g1r.Compressed()
	assert.Len(t, g1rbytes, c.CompressedG1ByteSize)
	g1rback, err := c.NewG1FromCompressed(g1rbytes)
	assert.NoError(t, err)
	assert.True(t, g1r.Equals(g1rback))
	assert.Len(t, g1rback.Bytes(), c.G1ByteSize, fmt.Sprintf("failed with curve %T", c.c))
	assert.Len(t, g1rback.Compressed(), c.CompressedG1ByteSize, fmt.Sprintf("failed with curve %T", c.c))

	g2r := c.GenG2.Mul(r)
	g2rbytes := g2r.Compressed()
	assert.Len(t, g2rbytes, c.CompressedG2ByteSize)
	g2rback, err := c.NewG2FromCompressed(g2rbytes)
	assert.NoError(t, err)
	assert.True(t, g2r.Equals(g2rback))
	assert.Len(t, g2rback.Bytes(), c.G2ByteSize, fmt.Sprintf("failed with curve %T", c.c))
	assert.Len(t, g2rback.Compressed(), c.CompressedG2ByteSize, fmt.Sprintf("failed with curve %T", c.c))

	g1rback, err = c.NewG1FromCompressed(nil)
	assert.Nil(t, g1rback)
	assert.Error(t, err)

	g2rback, err = c.NewG2FromCompressed(nil)
	assert.Nil(t, g2rback)
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

func runMulTest(t *testing.T, c *Curve) {
	rng, err := c.Rand()
	assert.NoError(t, err)

	r := c.NewRandomZr(rng)
	rInv := r.Copy()
	rInv.InvModP(c.GroupOrder)
	assert.True(t, r.Mul(rInv).Equals(c.NewZrFromInt(1)))

	rr := r.Mul(r)   // r^2
	rrr := rr.Mul(r) // r^3
	r3 := r.PowMod(c.NewZrFromInt(3))
	assert.True(t, rrr.Equals(r3))
}

func runQuadDHTestPairing(t *testing.T, c *Curve) {
	rng, err := c.Rand()
	assert.NoError(t, err)
	x := c.NewRandomZr(rng)
	y := c.NewRandomZr(rng)
	z := c.NewRandomZr(rng)
	w := c.NewRandomZr(rng)

	gx := c.GenG1.Mul(x)
	gy := c.GenG1.Mul(y)
	gz := c.GenG2.Mul(z)
	gw := c.GenG2.Mul(w)

	gyx := c.GenG1.Mul(y.Mul(x))
	gwz := c.GenG2.Mul(w.Mul(z))

	assert.True(t, gx.Mul(y).Equals(gyx))
	assert.True(t, gz.Mul(w).Equals(gwz))

	gtwy := c.Pairing(gw, gy)
	gtwy = c.FExp(gtwy)

	gtxyzw := gtwy.Exp(x).Exp(z)

	gtzx := c.Pairing(gz, gx)
	c.FExp(gtzx)

	xyzw := x.Mul(y).Mul(z).Mul(w)
	gt := c.Pairing(c.GenG2, c.GenG1)
	gt = c.FExp(gt)

	assert.True(t, gtxyzw.Equals(gt.Exp(xyzw)))
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
		runToFroCompressedTest(t, curve)
		runModAddSubNegTest(t, curve)
		runDHTestG1(t, curve)
		runDHTestG2(t, curve)
		runCopyCloneTest(t, curve)
		runJsonMarshaler(t, curve)
		runPowTest(t, curve)
		runMulTest(t, curve)
		runQuadDHTestPairing(t, curve)
	}
}

func Test381Compat(t *testing.T) {
	rng, err := Curves[BLS12_381].Rand()
	assert.NoError(t, err)

	kilic := Curves[BLS12_381]
	gurvy := Curves[BLS12_381_GURVY]

	rk := kilic.NewRandomZr(rng)
	rg := gurvy.NewZrFromBytes(rk.Bytes())
	assert.Equal(t, rk.Bytes(), rg.Bytes())

	g1g := gurvy.GenG1.Mul(rg)
	g1k := kilic.GenG1.Mul(rk)
	assert.Equal(t, g1g.Bytes(), g1k.Bytes())
	assert.Equal(t, g1g.Compressed(), g1k.Compressed())

	g2g := gurvy.GenG2.Mul(rg)
	g2k := kilic.GenG2.Mul(rk)
	assert.Equal(t, g2g.Bytes(), g2k.Bytes())
	assert.Equal(t, g2g.Compressed(), g2k.Compressed())

	gtg := gurvy.GenGt.Exp(rg)
	gtk := kilic.GenGt.Exp(rk)
	assert.Equal(t, gtg.Bytes(), gtk.Bytes())

	hg := gurvy.HashToG1([]byte("Chase!"))
	hk := kilic.HashToG1([]byte("Chase!"))
	assert.Equal(t, hg.Bytes(), hk.Bytes())

	hg = gurvy.HashToG1WithDomain([]byte("CD"), []byte("EF"))
	hk = kilic.HashToG1WithDomain([]byte("CD"), []byte("EF"))
	assert.Equal(t, hg.Bytes(), hk.Bytes())
}

func Test381BBSCompat(t *testing.T) {
	rng, err := Curves[BLS12_381_BBS].Rand()
	assert.NoError(t, err)

	kilic := Curves[BLS12_381_BBS]
	gurvy := Curves[BLS12_381_BBS_GURVY]

	rk := kilic.NewRandomZr(rng)
	rg := gurvy.NewZrFromBytes(rk.Bytes())
	assert.Equal(t, rk.Bytes(), rg.Bytes())

	g1g := gurvy.GenG1.Mul(rg)
	g1k := kilic.GenG1.Mul(rk)
	assert.Equal(t, g1g.Bytes(), g1k.Bytes())
	assert.Equal(t, g1g.Compressed(), g1k.Compressed())

	g2g := gurvy.GenG2.Mul(rg)
	g2k := kilic.GenG2.Mul(rk)
	assert.Equal(t, g2g.Bytes(), g2k.Bytes())
	assert.Equal(t, g2g.Compressed(), g2k.Compressed())

	gtg := gurvy.GenGt.Exp(rg)
	gtk := kilic.GenGt.Exp(rk)
	assert.Equal(t, gtg.Bytes(), gtk.Bytes())

	hg := gurvy.HashToG1([]byte("Chase!"))
	hk := kilic.HashToG1([]byte("Chase!"))
	assert.Equal(t, hg.Bytes(), hk.Bytes())

	hg = gurvy.HashToG1WithDomain([]byte("CD"), []byte("EF"))
	hk = kilic.HashToG1WithDomain([]byte("CD"), []byte("EF"))
	assert.Equal(t, hg.Bytes(), hk.Bytes())
}
