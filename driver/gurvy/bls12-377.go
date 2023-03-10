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
	"strings"

	"github.com/IBM/mathlib/driver"
	"github.com/IBM/mathlib/driver/common"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
)

/*********************************************************************/

type bls12377Zr struct {
	*big.Int
}

func (z *bls12377Zr) Plus(a driver.Zr) driver.Zr {
	return &bls12377Zr{new(big.Int).Add(z.Int, a.(*bls12377Zr).Int)}
}

func (z *bls12377Zr) Mul(a driver.Zr) driver.Zr {
	prod := new(big.Int).Mul(z.Int, a.(*bls12377Zr).Int)
	return &bls12377Zr{prod.Mod(prod, fr.Modulus())}
}

func (z *bls12377Zr) Mod(a driver.Zr) {
	z.Int.Mod(z.Int, a.(*bls12377Zr).Int)
}

func (z *bls12377Zr) PowMod(x driver.Zr) driver.Zr {
	return &bls12377Zr{new(big.Int).Exp(z.Int, x.(*bls12377Zr).Int, fr.Modulus())}
}

func (z *bls12377Zr) InvModP(a driver.Zr) {
	z.Int.ModInverse(z.Int, a.(*bls12377Zr).Int)
}

func (z *bls12377Zr) Bytes() []byte {
	return common.BigToBytes(z.Int)
}

func (z *bls12377Zr) Equals(a driver.Zr) bool {
	return z.Int.Cmp(a.(*bls12377Zr).Int) == 0
}

func (z *bls12377Zr) Copy() driver.Zr {
	return &bls12377Zr{new(big.Int).Set(z.Int)}
}

func (z *bls12377Zr) Clone(a driver.Zr) {
	raw := a.(*bls12377Zr).Int.Bytes()
	z.Int.SetBytes(raw)
}

func (z *bls12377Zr) String() string {
	return z.Int.Text(16)
}

/*********************************************************************/

type bls12377G1 struct {
	*bls12377.G1Affine
}

func (g *bls12377G1) Clone(a driver.G1) {
	raw := a.(*bls12377G1).G1Affine.Bytes()
	_, err := g.SetBytes(raw[:])
	if err != nil {
		panic("could not copy point")
	}
}

func (e *bls12377G1) Copy() driver.G1 {
	c := &bls12377.G1Affine{}
	c.Set(e.G1Affine)
	return &bls12377G1{c}
}

func (g *bls12377G1) Add(a driver.G1) {
	j := &bls12377.G1Jac{}
	j.FromAffine(g.G1Affine)
	j.AddMixed((*bls12377.G1Affine)(a.(*bls12377G1).G1Affine))
	g.G1Affine.FromJacobian(j)
}

func (g *bls12377G1) Mul(a driver.Zr) driver.G1 {
	gc := &bls12377G1{&bls12377.G1Affine{}}
	gc.Clone(g)
	gc.G1Affine.ScalarMultiplication(g.G1Affine, a.(*bls12377Zr).Int)

	return gc
}

func (g *bls12377G1) Mul2(e driver.Zr, Q driver.G1, f driver.Zr) driver.G1 {
	a := g.Mul(e)
	b := Q.Mul(f)
	a.Add(b)

	return a
}

func (g *bls12377G1) Equals(a driver.G1) bool {
	return g.G1Affine.Equal(a.(*bls12377G1).G1Affine)
}

func (g *bls12377G1) Bytes() []byte {
	raw := g.G1Affine.RawBytes()
	return raw[:]
}

func (g *bls12377G1) Sub(a driver.G1) {
	j, k := &bls12377.G1Jac{}, &bls12377.G1Jac{}
	j.FromAffine(g.G1Affine)
	k.FromAffine(a.(*bls12377G1).G1Affine)
	j.SubAssign(k)
	g.G1Affine.FromJacobian(j)
}

func (g *bls12377G1) IsInfinity() bool {
	return g.G1Affine.IsInfinity()
}

func (g *bls12377G1) String() string {
	rawstr := g.G1Affine.String()
	m := g1StrRegexp.FindAllStringSubmatch(rawstr, -1)
	return "(" + strings.TrimLeft(m[0][1], "0") + "," + strings.TrimLeft(m[0][2], "0") + ")"
}

/*********************************************************************/

type bls12377G2 struct {
	*bls12377.G2Affine
}

func (g *bls12377G2) Clone(a driver.G2) {
	raw := a.(*bls12377G2).G2Affine.Bytes()
	_, err := g.SetBytes(raw[:])
	if err != nil {
		panic("could not copy point")
	}
}

func (e *bls12377G2) Copy() driver.G2 {
	c := &bls12377.G2Affine{}
	c.Set(e.G2Affine)
	return &bls12377G2{c}
}

func (g *bls12377G2) Mul(a driver.Zr) driver.G2 {
	gc := &bls12377G2{&bls12377.G2Affine{}}
	gc.Clone(g)
	gc.G2Affine.ScalarMultiplication(g.G2Affine, a.(*bls12377Zr).Int)

	return gc
}

func (g *bls12377G2) Add(a driver.G2) {
	j := &bls12377.G2Jac{}
	j.FromAffine(g.G2Affine)
	j.AddMixed((*bls12377.G2Affine)(a.(*bls12377G2).G2Affine))
	g.G2Affine.FromJacobian(j)
}

func (g *bls12377G2) Sub(a driver.G2) {
	j := &bls12377.G2Jac{}
	j.FromAffine(g.G2Affine)
	aJac := &bls12377.G2Jac{}
	aJac.FromAffine((*bls12377.G2Affine)(a.(*bls12377G2).G2Affine))
	j.SubAssign(aJac)
	g.G2Affine.FromJacobian(j)
}

func (g *bls12377G2) Affine() {
	// we're always affine
}

func (g *bls12377G2) Bytes() []byte {
	raw := g.G2Affine.RawBytes()
	return raw[:]
}

func (g *bls12377G2) String() string {
	return g.G2Affine.String()
}

func (g *bls12377G2) Equals(a driver.G2) bool {
	return g.G2Affine.Equal(a.(*bls12377G2).G2Affine)
}

/*********************************************************************/

type bls12377Gt struct {
	*bls12377.GT
}

func (g *bls12377Gt) Exp(x driver.Zr) driver.Gt {
	copy := &bls12377.GT{}
	copy.Set(g.GT)
	return &bls12377Gt{copy.Exp(*g.GT, x.(*bls12377Zr).Int)}
}

func (g *bls12377Gt) Equals(a driver.Gt) bool {
	return g.GT.Equal(a.(*bls12377Gt).GT)
}

func (g *bls12377Gt) Inverse() {
	g.GT.Inverse(g.GT)
}

func (g *bls12377Gt) Mul(a driver.Gt) {
	g.GT.Mul(g.GT, a.(*bls12377Gt).GT)
}

func (g *bls12377Gt) IsUnity() bool {
	unity := &bls12377.GT{}
	unity.SetOne()

	return unity.Equal(g.GT)
}

func (g *bls12377Gt) ToString() string {
	return g.GT.String()
}

func (g *bls12377Gt) Bytes() []byte {
	raw := g.GT.Bytes()
	return raw[:]
}

/*********************************************************************/

type Bls12_377 struct {
}

func (c *Bls12_377) Pairing(p2 driver.G2, p1 driver.G1) driver.Gt {
	t, err := bls12377.MillerLoop([]bls12377.G1Affine{*p1.(*bls12377G1).G1Affine}, []bls12377.G2Affine{*p2.(*bls12377G2).G2Affine})
	if err != nil {
		panic(fmt.Sprintf("pairing failed [%s]", err.Error()))
	}

	return &bls12377Gt{&t}
}

func (c *Bls12_377) Pairing2(p2a, p2b driver.G2, p1a, p1b driver.G1) driver.Gt {
	t, err := bls12377.MillerLoop([]bls12377.G1Affine{*p1a.(*bls12377G1).G1Affine, *p1b.(*bls12377G1).G1Affine}, []bls12377.G2Affine{*p2a.(*bls12377G2).G2Affine, *p2b.(*bls12377G2).G2Affine})
	if err != nil {
		panic(fmt.Sprintf("pairing 2 failed [%s]", err.Error()))
	}

	return &bls12377Gt{&t}
}

func (c *Bls12_377) FExp(a driver.Gt) driver.Gt {
	gt := bls12377.FinalExponentiation(a.(*bls12377Gt).GT)
	return &bls12377Gt{&gt}
}

func (*Bls12_377) ModAdd(a, b, m driver.Zr) driver.Zr {
	c := a.Plus(b)
	c.Mod(m)
	return c
}

func (c *Bls12_377) ModSub(a, b, m driver.Zr) driver.Zr {
	return c.ModAdd(a, c.ModNeg(b, m), m)
}

func (c *Bls12_377) ModNeg(a1, m driver.Zr) driver.Zr {
	a := a1.Copy()
	a.Mod(m)
	return &bls12377Zr{a.(*bls12377Zr).Int.Sub(m.(*bls12377Zr).Int, a.(*bls12377Zr).Int)}
}

func (c *Bls12_377) ModMul(a1, b1, m driver.Zr) driver.Zr {
	a := a1.Copy()
	b := b1.Copy()
	a.Mod(m)
	b.Mod(m)
	return &bls12377Zr{a.(*bls12377Zr).Int.Mul(a.(*bls12377Zr).Int, b.(*bls12377Zr).Int)}
}

func (c *Bls12_377) GenG1() driver.G1 {
	_, _, g1, _ := bls12377.Generators()
	raw := g1.Bytes()

	r := &bls12377.G1Affine{}
	_, err := r.SetBytes(raw[:])
	if err != nil {
		panic("could not generate point")
	}

	return &bls12377G1{r}
}

func (c *Bls12_377) GenG2() driver.G2 {
	_, _, _, g2 := bls12377.Generators()
	raw := g2.Bytes()

	r := &bls12377.G2Affine{}
	_, err := r.SetBytes(raw[:])
	if err != nil {
		panic("could not generate point")
	}

	return &bls12377G2{r}
}

func (c *Bls12_377) GenGt() driver.Gt {
	g1 := c.GenG1()
	g2 := c.GenG2()
	gengt := c.Pairing(g2, g1)
	gengt = c.FExp(gengt)
	return gengt
}

func (c *Bls12_377) GroupOrder() driver.Zr {
	return &bls12377Zr{fr.Modulus()}
}

func (c *Bls12_377) CoordinateByteSize() int {
	return 48
}

func (c *Bls12_377) ScalarByteSize() int {
	return 32
}

func (c *Bls12_377) NewG1() driver.G1 {
	return &bls12377G1{&bls12377.G1Affine{}}
}

func (c *Bls12_377) NewG2() driver.G2 {
	return &bls12377G2{&bls12377.G2Affine{}}
}

func (c *Bls12_377) NewG1FromCoords(ix, iy driver.Zr) driver.G1 {
	return nil
}

func (c *Bls12_377) NewZrFromBytes(b []byte) driver.Zr {
	return &bls12377Zr{new(big.Int).SetBytes(b)}
}

func (c *Bls12_377) NewZrFromInt(i int64) driver.Zr {
	return &bls12377Zr{big.NewInt(i)}
}

func (c *Bls12_377) NewG1FromBytes(b []byte) driver.G1 {
	v := &bls12377.G1Affine{}
	_, err := v.SetBytes(b)
	if err != nil {
		panic(fmt.Sprintf("set bytes failed [%s]", err.Error()))
	}

	return &bls12377G1{v}
}

func (c *Bls12_377) NewG2FromBytes(b []byte) driver.G2 {
	v := &bls12377.G2Affine{}
	_, err := v.SetBytes(b)
	if err != nil {
		panic(fmt.Sprintf("set bytes failed [%s]", err.Error()))
	}

	return &bls12377G2{v}
}

func (c *Bls12_377) NewGtFromBytes(b []byte) driver.Gt {
	v := &bls12377.GT{}
	err := v.SetBytes(b)
	if err != nil {
		panic(fmt.Sprintf("set bytes failed [%s]", err.Error()))
	}

	return &bls12377Gt{v}
}

func (c *Bls12_377) HashToZr(data []byte) driver.Zr {
	digest := sha256.Sum256(data)
	digestBig := c.NewZrFromBytes(digest[:])
	digestBig.Mod(c.GroupOrder())
	return digestBig
}

func (c *Bls12_377) HashToG1(data []byte) driver.G1 {
	g1, err := bls12377.HashToG1(data, []byte{})
	if err != nil {
		panic(fmt.Sprintf("HashToG1 failed [%s]", err.Error()))
	}

	return &bls12377G1{&g1}
}

func (c *Bls12_377) NewRandomZr(rng io.Reader) driver.Zr {
	res := new(big.Int)
	v := &fr.Element{}
	_, err := v.SetRandom()
	if err != nil {
		panic(err)
	}

	return &bls12377Zr{v.ToBigIntRegular(res)}
}

func (c *Bls12_377) Rand() (io.Reader, error) {
	return rand.Reader, nil
}