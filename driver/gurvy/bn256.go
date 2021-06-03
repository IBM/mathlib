/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gurvy

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"strings"

	"github.com/IBM/mathlib/driver"
	"github.com/IBM/mathlib/driver/common"
	"github.com/consensys/gurvy/bn256"
	"github.com/consensys/gurvy/bn256/fr"
)

/*********************************************************************/

type bn256Zr struct {
	*big.Int
}

func (z *bn256Zr) Plus(a driver.Zr) driver.Zr {
	return &bn256Zr{new(big.Int).Add(z.Int, a.(*bn256Zr).Int)}
}

func (z *bn256Zr) Mod(a driver.Zr) {
	z.Int.Mod(z.Int, a.(*bn256Zr).Int)
}

func (z *bn256Zr) PowMod(x driver.Zr) driver.Zr {
	return &bn256Zr{new(big.Int).Exp(z.Int, x.(*bn256Zr).Int, fr.Modulus())}
}

func (z *bn256Zr) InvModP(a driver.Zr) {
	z.Int.ModInverse(z.Int, a.(*bn256Zr).Int)
}

func (z *bn256Zr) Bytes() []byte {
	return common.BigToBytes(z.Int)
}

func (z *bn256Zr) Equals(a driver.Zr) bool {
	return z.Int.Cmp(a.(*bn256Zr).Int) == 0
}

func (z *bn256Zr) Copy() driver.Zr {
	return &bn256Zr{new(big.Int).Set(z.Int)}
}

func (z *bn256Zr) Clone(a driver.Zr) {
	raw := a.(*bn256Zr).Int.Bytes()
	z.Int.SetBytes(raw)
}

func (z *bn256Zr) String() string {
	return z.Int.Text(16)
}

/*********************************************************************/

type bn256G1 struct {
	*bn256.G1Affine
}

func (g *bn256G1) Clone(a driver.G1) {
	raw := a.(*bn256G1).G1Affine.Bytes()
	_, err := g.SetBytes(raw[:])
	if err != nil {
		panic("could not copy point")
	}
}

func (e *bn256G1) Copy() driver.G1 {
	c := &bn256.G1Affine{}
	c.Set(e.G1Affine)
	return &bn256G1{c}
}

func (g *bn256G1) Add(a driver.G1) {
	j := &bn256.G1Jac{}
	j.FromAffine(g.G1Affine)
	j.AddMixed((*bn256.G1Affine)(a.(*bn256G1).G1Affine))
	g.G1Affine.FromJacobian(j)
}

func (g *bn256G1) Mul(a driver.Zr) driver.G1 {
	gc := &bn256G1{&bn256.G1Affine{}}
	gc.Clone(g)
	gc.G1Affine.ScalarMultiplication(g.G1Affine, a.(*bn256Zr).Int)

	return gc
}

func (g *bn256G1) Mul2(e driver.Zr, Q driver.G1, f driver.Zr) driver.G1 {
	a := g.Mul(e)
	b := Q.Mul(f)
	a.Add(b)

	return a
}

func (g *bn256G1) Equals(a driver.G1) bool {
	return g.G1Affine.Equal(a.(*bn256G1).G1Affine)
}

func (g *bn256G1) Bytes() []byte {
	raw := g.G1Affine.RawBytes()
	return raw[:]
}

func (g *bn256G1) Sub(a driver.G1) {
	j, k := &bn256.G1Jac{}, &bn256.G1Jac{}
	j.FromAffine(g.G1Affine)
	k.FromAffine(a.(*bn256G1).G1Affine)
	j.SubAssign(k)
	g.G1Affine.FromJacobian(j)
}

func (g *bn256G1) IsInfinity() bool {
	return g.G1Affine.IsInfinity()
}

var g1StrRegexp *regexp.Regexp = regexp.MustCompile(`^E\([[]([0-9]+),([0-9]+)[]]\),$`)

func (g *bn256G1) String() string {
	rawstr := g.G1Affine.String()
	m := g1StrRegexp.FindAllStringSubmatch(rawstr, -1)
	return "(" + strings.TrimLeft(m[0][1], "0") + "," + strings.TrimLeft(m[0][2], "0") + ")"
}

/*********************************************************************/

type bn256G2 struct {
	*bn256.G2Affine
}

func (g *bn256G2) Clone(a driver.G2) {
	raw := a.(*bn256G2).G2Affine.Bytes()
	_, err := g.SetBytes(raw[:])
	if err != nil {
		panic("could not copy point")
	}
}

func (e *bn256G2) Copy() driver.G2 {
	c := &bn256.G2Affine{}
	c.Set(e.G2Affine)
	return &bn256G2{c}
}

func (g *bn256G2) Mul(a driver.Zr) driver.G2 {
	gc := &bn256G2{&bn256.G2Affine{}}
	gc.Clone(g)
	gc.G2Affine.ScalarMultiplication(g.G2Affine, a.(*bn256Zr).Int)

	return gc
}

func (g *bn256G2) Add(a driver.G2) {
	j := &bn256.G2Jac{}
	j.FromAffine(g.G2Affine)
	j.AddMixed((*bn256.G2Affine)(a.(*bn256G2).G2Affine))
	g.G2Affine.FromJacobian(j)
}

func (g *bn256G2) Sub(a driver.G2) {
	j := &bn256.G2Jac{}
	j.FromAffine(g.G2Affine)
	aJac := &bn256.G2Jac{}
	aJac.FromAffine((*bn256.G2Affine)(a.(*bn256G2).G2Affine))
	j.SubAssign(aJac)
	g.G2Affine.FromJacobian(j)
}

func (g *bn256G2) Affine() {
	// we're always affine
}

func (g *bn256G2) Bytes() []byte {
	raw := g.G2Affine.RawBytes()
	return raw[:]
}

func (g *bn256G2) String() string {
	return g.G2Affine.String()
}

func (g *bn256G2) Equals(a driver.G2) bool {
	return g.G2Affine.Equal(a.(*bn256G2).G2Affine)
}

/*********************************************************************/

type bn256Gt struct {
	*bn256.GT
}

func (g *bn256Gt) Equals(a driver.Gt) bool {
	return g.GT.Equal(a.(*bn256Gt).GT)
}

func (g *bn256Gt) Inverse() {
	g.GT.Inverse(g.GT)
}

func (g *bn256Gt) Mul(a driver.Gt) {
	g.GT.Mul(g.GT, a.(*bn256Gt).GT)
}

func (g *bn256Gt) IsUnity() bool {
	unity := &bn256.GT{}
	unity.SetOne()

	return unity.Equal(g.GT)
}

func (g *bn256Gt) ToString() string {
	return g.GT.String()
}

func (g *bn256Gt) Bytes() []byte {
	raw := g.GT.Bytes()
	return raw[:]
}

/*********************************************************************/

type Bn256 struct {
}

func (c *Bn256) Pairing(p2 driver.G2, p1 driver.G1) driver.Gt {
	t, err := bn256.MillerLoop([]bn256.G1Affine{*p1.(*bn256G1).G1Affine}, []bn256.G2Affine{*p2.(*bn256G2).G2Affine})
	if err != nil {
		panic(fmt.Sprintf("pairing failed [%s]", err.Error()))
	}

	return &bn256Gt{&t}
}

func (c *Bn256) Pairing2(p2a, p2b driver.G2, p1a, p1b driver.G1) driver.Gt {
	t, err := bn256.MillerLoop([]bn256.G1Affine{*p1a.(*bn256G1).G1Affine, *p1b.(*bn256G1).G1Affine}, []bn256.G2Affine{*p2a.(*bn256G2).G2Affine, *p2b.(*bn256G2).G2Affine})
	if err != nil {
		panic(fmt.Sprintf("pairing 2 failed [%s]", err.Error()))
	}

	return &bn256Gt{&t}
}

func (c *Bn256) FExp(a driver.Gt) driver.Gt {
	gt := bn256.FinalExponentiation(a.(*bn256Gt).GT)
	return &bn256Gt{&gt}
}

func (*Bn256) ModAdd(a, b, m driver.Zr) driver.Zr {
	c := a.Plus(b)
	c.Mod(m)
	return c
}

func (c *Bn256) ModSub(a, b, m driver.Zr) driver.Zr {
	return c.ModAdd(a, c.ModNeg(b, m), m)
}

func (c *Bn256) ModNeg(a1, m driver.Zr) driver.Zr {
	a := a1.Copy()
	a.Mod(m)
	return &bn256Zr{a.(*bn256Zr).Int.Sub(m.(*bn256Zr).Int, a.(*bn256Zr).Int)}
}

func (c *Bn256) ModMul(a1, b1, m driver.Zr) driver.Zr {
	a := a1.Copy()
	b := b1.Copy()
	a.Mod(m)
	b.Mod(m)
	return &bn256Zr{a.(*bn256Zr).Int.Mul(a.(*bn256Zr).Int, b.(*bn256Zr).Int)}
}

func (c *Bn256) GenG1() driver.G1 {
	_, _, g1, _ := bn256.Generators()
	raw := g1.Bytes()

	r := &bn256.G1Affine{}
	_, err := r.SetBytes(raw[:])
	if err != nil {
		panic("could not generate point")
	}

	return &bn256G1{r}
}

func (c *Bn256) GenG2() driver.G2 {
	_, _, _, g2 := bn256.Generators()
	raw := g2.Bytes()

	r := &bn256.G2Affine{}
	_, err := r.SetBytes(raw[:])
	if err != nil {
		panic("could not generate point")
	}

	return &bn256G2{r}
}

func (c *Bn256) GenGt() driver.Gt {
	g1 := c.GenG1()
	g2 := c.GenG2()
	gengt := c.Pairing(g2, g1)
	gengt = c.FExp(gengt)
	return gengt
}

func (c *Bn256) GroupOrder() driver.Zr {
	return &bn256Zr{fr.Modulus()}
}

func (c *Bn256) FieldBytes() int {
	return 32
}

func (c *Bn256) NewG1() driver.G1 {
	return &bn256G1{&bn256.G1Affine{}}
}

func (c *Bn256) NewG2() driver.G2 {
	return &bn256G2{&bn256.G2Affine{}}
}

func (c *Bn256) NewG1FromCoords(ix, iy driver.Zr) driver.G1 {
	return nil
}

func (c *Bn256) NewZrFromBytes(b []byte) driver.Zr {
	return &bn256Zr{new(big.Int).SetBytes(b)}
}

func (c *Bn256) NewZrFromInt(i int64) driver.Zr {
	return &bn256Zr{big.NewInt(i)}
}

func (c *Bn256) NewG1FromBytes(b []byte) driver.G1 {
	v := &bn256.G1Affine{}
	_, err := v.SetBytes(b)
	if err != nil {
		panic(fmt.Sprintf("set bytes failed [%s]", err.Error()))
	}

	return &bn256G1{v}
}

func (c *Bn256) NewG2FromBytes(b []byte) driver.G2 {
	v := &bn256.G2Affine{}
	_, err := v.SetBytes(b)
	if err != nil {
		panic(fmt.Sprintf("set bytes failed [%s]", err.Error()))
	}

	return &bn256G2{v}
}

func (c *Bn256) NewGtFromBytes(b []byte) driver.Gt {
	v := &bn256.GT{}
	err := v.SetBytes(b)
	if err != nil {
		panic(fmt.Sprintf("set bytes failed [%s]", err.Error()))
	}

	return &bn256Gt{v}
}

func (c *Bn256) HashToZr(data []byte) driver.Zr {
	digest := sha256.Sum256(data)
	digestBig := c.NewZrFromBytes(digest[:])
	digestBig.Mod(c.GroupOrder())
	return digestBig
}

func (c *Bn256) HashToG1(data []byte) driver.G1 {
	g1, err := bn256.HashToCurveG1Svdw(data, []byte{})
	if err != nil {
		panic(fmt.Sprintf("HashToG1 failed [%s]", err.Error()))
	}

	return &bn256G1{&g1}
}

func (c *Bn256) NewRandomZr(rng io.Reader) driver.Zr {
	res := new(big.Int)
	v := &fr.Element{}
	_, err := v.SetRandom()
	if err != nil {
		panic(err)
	}

	return &bn256Zr{v.ToBigIntRegular(res)}
}

func (c *Bn256) Rand() (io.Reader, error) {
	return rand.Reader, nil
}
