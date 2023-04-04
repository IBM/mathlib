/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kilic

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"

	"github.com/IBM/mathlib/driver"
	bls12381 "github.com/kilic/bls12-381"
)

/*********************************************************************/

var qbls381 = bls12381.Fr{0xffffffff00000001, 0x53bda402fffe5bfe, 0x3339d80809a1d805, 0x73eda753299d7d48}
var qbls381Big = bls12381.NewG1().Q()

func fromBig(in *big.Int) *bls12381.Fr {
	e := bls12381.NewFr()
	e.Zero()
	_in := new(big.Int).Set(in)
	zero := new(big.Int)
	c0 := _in.Cmp(zero)
	c1 := _in.Cmp(qbls381Big)
	if c0 == -1 || c1 == 1 {
		_in.Mod(_in, qbls381Big)
	}
	words := _in.Bits()
	for i := 0; i < len(words); i++ {
		e[i] = uint64(words[i])
	}
	return e
}

type bls12_381Zr struct {
	*bls12381.Fr
}

func (z *bls12_381Zr) Plus(a driver.Zr) driver.Zr {
	fr := bls12381.NewFr()
	fr.Add(z.Fr, a.(*bls12_381Zr).Fr)
	return &bls12_381Zr{fr}
}

func (z *bls12_381Zr) Mul(a driver.Zr) driver.Zr {
	fr := bls12381.NewFr()
	fr.Mul(z.Fr, a.(*bls12_381Zr).Fr)
	return &bls12_381Zr{fr}
}

func (z *bls12_381Zr) Mod(a driver.Zr) {
	abig := a.(*bls12_381Zr).Fr.ToBig()
	zBig := z.Fr.ToBig()
	res := zBig.Mod(zBig, abig)
	z.Fr = fromBig(res)
}

func (z *bls12_381Zr) PowMod(x driver.Zr) driver.Zr {
	fr := bls12381.NewFr()
	big := x.(*bls12_381Zr).Fr.ToBig()
	fr.Exp(z.Fr, big)
	return &bls12_381Zr{fr}
}

func (z *bls12_381Zr) InvModP(a driver.Zr) {
	abig := a.(*bls12_381Zr).Fr.ToBig()
	zBig := z.Fr.ToBig()
	res := zBig.ModInverse(zBig, abig)
	z.Fr = fromBig(res)
}

func (z *bls12_381Zr) Bytes() []byte {
	return z.Fr.ToBytes()
}

func (z *bls12_381Zr) Equals(a driver.Zr) bool {
	return z.Fr.Cmp(a.(*bls12_381Zr).Fr) == 0
}

func (z *bls12_381Zr) Copy() driver.Zr {
	return &bls12_381Zr{bls12381.NewFr().Set(z.Fr)}
}

func (z *bls12_381Zr) Clone(a driver.Zr) {
	z.Fr.Set(a.(*bls12_381Zr).Fr)
}

func (z *bls12_381Zr) String() string {
	return z.Fr.ToBig().Text(16)
}

/*********************************************************************/

type bls12_381G1 struct {
	*bls12381.PointG1
}

func (g *bls12_381G1) Clone(a driver.G1) {
	g.Set(a.(*bls12_381G1).PointG1)
}

func (e *bls12_381G1) Copy() driver.G1 {
	c := &bls12381.PointG1{}
	c.Set(e.PointG1)
	return &bls12_381G1{c}
}

func (g *bls12_381G1) Add(a driver.G1) {
	g1 := bls12381.NewG1()
	res := g1.New()
	g1.Add(res, g.PointG1, a.(*bls12_381G1).PointG1)
	g.PointG1 = res
}

func (g *bls12_381G1) Mul(a driver.Zr) driver.G1 {
	g1 := bls12381.NewG1()
	res := g1.New()

	g1.MulScalar(res, g.PointG1, a.(*bls12_381Zr).Fr)

	return &bls12_381G1{res}
}

func (g *bls12_381G1) Mul2(e driver.Zr, Q driver.G1, f driver.Zr) driver.G1 {
	a := g.Mul(e)
	b := Q.Mul(f)
	a.Add(b)

	return a
}

func (g *bls12_381G1) Equals(a driver.G1) bool {
	g1 := bls12381.NewG1()
	return g1.Equal(a.(*bls12_381G1).PointG1, g.PointG1)
}

func (g *bls12_381G1) Bytes() []byte {
	g1 := bls12381.NewG1()
	raw := g1.ToBytes(g.PointG1)
	return raw[:]
}

func (g *bls12_381G1) Compressed() []byte {
	g1 := bls12381.NewG1()
	raw := g1.ToCompressed(g.PointG1)
	return raw[:]
}

func (g *bls12_381G1) Sub(a driver.G1) {
	g1 := bls12381.NewG1()
	res := g1.New()
	g1.Sub(res, g.PointG1, a.(*bls12_381G1).PointG1)
	g.PointG1 = res
}

func (g *bls12_381G1) IsInfinity() bool {
	g1 := bls12381.NewG1()
	return g1.IsZero(g.PointG1)
}

func (g *bls12_381G1) String() string {
	gb := g.Bytes()
	x := new(big.Int).SetBytes(gb[:len(gb)/2])
	y := new(big.Int).SetBytes(gb[len(gb)/2:])

	return "(" + x.String() + "," + y.String() + ")"
}

/*********************************************************************/

type bls12_381G2 struct {
	*bls12381.PointG2
}

func (g *bls12_381G2) Clone(a driver.G2) {
	g.Set(a.(*bls12_381G2).PointG2)
}

func (e *bls12_381G2) Copy() driver.G2 {
	c := &bls12381.PointG2{}
	c.Set(e.PointG2)
	return &bls12_381G2{c}
}

func (g *bls12_381G2) Mul(a driver.Zr) driver.G2 {
	g2 := bls12381.NewG2()
	res := g2.New()

	g2.MulScalar(res, g.PointG2, a.(*bls12_381Zr).Fr)

	return &bls12_381G2{res}
}

func (g *bls12_381G2) Add(a driver.G2) {
	g2 := bls12381.NewG2()
	res := g2.New()
	g2.Add(res, g.PointG2, a.(*bls12_381G2).PointG2)
	g.PointG2 = res
}

func (g *bls12_381G2) Sub(a driver.G2) {
	g2 := bls12381.NewG2()
	res := g2.New()
	g2.Sub(res, g.PointG2, a.(*bls12_381G2).PointG2)
	g.PointG2 = res
}

func (g *bls12_381G2) Affine() {
	g2 := bls12381.NewG2()
	g.PointG2 = g2.Affine(g.PointG2)
}

func (g *bls12_381G2) Bytes() []byte {
	g2 := bls12381.NewG2()
	raw := g2.ToUncompressed(g.PointG2)
	return raw[:]
}

func (g *bls12_381G2) Compressed() []byte {
	g2 := bls12381.NewG2()
	raw := g2.ToCompressed(g.PointG2)
	return raw[:]
}

func (g *bls12_381G2) String() string {
	// FIXME
	return ""
}

func (g *bls12_381G2) Equals(a driver.G2) bool {
	g2 := bls12381.NewG2()
	return g2.Equal(a.(*bls12_381G2).PointG2, g.PointG2)
}

/*********************************************************************/

type bls12_381Gt struct {
	*bls12381.E
}

func (g *bls12_381Gt) Exp(x driver.Zr) driver.Gt {
	gt := bls12381.NewGT()
	res := gt.New()
	gt.Exp(res, g.E, x.(*bls12_381Zr).Fr.ToBig())

	return &bls12_381Gt{res}
}

func (g *bls12_381Gt) Equals(a driver.Gt) bool {
	return a.(*bls12_381Gt).E.Equal(g.E)
}

func (g *bls12_381Gt) Inverse() {
	gt := bls12381.NewGT()
	res := gt.New()
	gt.Inverse(res, g.E)
	g.E = res
}

func (g *bls12_381Gt) Mul(a driver.Gt) {
	gt := bls12381.NewGT()
	res := gt.New()
	gt.Mul(res, g.E, a.(*bls12_381Gt).E)
	g.E = res
}

func (g *bls12_381Gt) IsUnity() bool {
	return g.E.IsOne()
}

func (g *bls12_381Gt) ToString() string {
	// FIXME
	return ""
}

func (g *bls12_381Gt) Bytes() []byte {
	gt := bls12381.NewGT()
	raw := gt.ToBytes(g.E)
	return raw[:]
}

/*********************************************************************/

type Bls12_381 struct {
}

func (c *Bls12_381) Pairing(p2 driver.G2, p1 driver.G1) driver.Gt {
	bls := bls12381.NewEngine()
	bls.AddPair(p1.(*bls12_381G1).PointG1, p2.(*bls12_381G2).PointG2)

	return &bls12_381Gt{bls.Result()}
}

func (c *Bls12_381) Pairing2(p2a, p2b driver.G2, p1a, p1b driver.G1) driver.Gt {
	bls := bls12381.NewEngine()
	bls.AddPair(p1a.(*bls12_381G1).PointG1, p2a.(*bls12_381G2).PointG2)
	bls.AddPair(p1b.(*bls12_381G1).PointG1, p2b.(*bls12_381G2).PointG2)

	return &bls12_381Gt{bls.Result()}
}

func (c *Bls12_381) FExp(a driver.Gt) driver.Gt {
	return a
}

func (*Bls12_381) ModAdd(a, b, m driver.Zr) driver.Zr {
	c := a.Plus(b)
	c.Mod(m)
	return c
}

func (c *Bls12_381) ModSub(a, b, m driver.Zr) driver.Zr {
	return c.ModAdd(a, c.ModNeg(b, m), m)
}

func (c *Bls12_381) ModNeg(a1, m driver.Zr) driver.Zr {
	res := bls12381.NewFr()
	res.Sub(m.(*bls12_381Zr).Fr, a1.(*bls12_381Zr).Fr)
	if res.Cmp(bls12381.NewFr().Zero()) < 0 {
		res.Add(res, &qbls381)
	}
	return &bls12_381Zr{res}
}

func (c *Bls12_381) ModMul(a1, b1, m driver.Zr) driver.Zr {
	res := a1.Mul(b1)
	res.Mod(m)
	return res
}

func (c *Bls12_381) GenG1() driver.G1 {
	g := bls12381.NewG1()
	g1 := g.One()
	return &bls12_381G1{g1}
}

func (c *Bls12_381) GenG2() driver.G2 {
	g := bls12381.NewG2()
	g2 := g.One()
	return &bls12_381G2{g2}
}

func (c *Bls12_381) GenGt() driver.Gt {
	g1 := c.GenG1()
	g2 := c.GenG2()
	gengt := c.Pairing(g2, g1)
	gengt = c.FExp(gengt)
	return gengt
}

func (c *Bls12_381) GroupOrder() driver.Zr {
	qcopy := qbls381
	return &bls12_381Zr{&qcopy}
}

func (c *Bls12_381) CoordinateByteSize() int {
	return 48
}

func (c *Bls12_381) ScalarByteSize() int {
	return 32
}

func (c *Bls12_381) NewG1() driver.G1 {
	return &bls12_381G1{&bls12381.PointG1{}}
}

func (c *Bls12_381) NewG2() driver.G2 {
	return &bls12_381G2{&bls12381.PointG2{}}
}

func (c *Bls12_381) NewG1FromCoords(ix, iy driver.Zr) driver.G1 {
	return nil
}

func (c *Bls12_381) NewZrFromBytes(b []byte) driver.Zr {
	return &bls12_381Zr{bls12381.NewFr().FromBytes(b)}
}

func (c *Bls12_381) NewZrFromInt(i int64) driver.Zr {
	bi := &big.Int{}
	bi.SetInt64(i)
	if i < 0 {
		bi.Add(bi, qbls381Big)
	}

	return &bls12_381Zr{fromBig(bi)}
}

func (c *Bls12_381) NewG1FromBytes(b []byte) driver.G1 {
	g1 := bls12381.NewG1()
	p, err := g1.FromBytes(b)
	if err != nil {
		panic(fmt.Sprintf("set bytes failed [%s]", err.Error()))
	}

	return &bls12_381G1{p}
}

func (c *Bls12_381) NewG2FromBytes(b []byte) driver.G2 {
	g2 := bls12381.NewG2()
	p, err := g2.FromUncompressed(b)
	if err != nil {
		panic(fmt.Sprintf("set bytes failed [%s]", err.Error()))
	}

	return &bls12_381G2{p}
}

func (c *Bls12_381) NewG1FromCompressed(b []byte) driver.G1 {
	g1 := bls12381.NewG1()
	p, err := g1.FromCompressed(b)
	if err != nil {
		panic(fmt.Sprintf("set bytes failed [%s]", err.Error()))
	}

	return &bls12_381G1{p}
}

func (c *Bls12_381) NewG2FromCompressed(b []byte) driver.G2 {
	g2 := bls12381.NewG2()
	p, err := g2.FromCompressed(b)
	if err != nil {
		panic(fmt.Sprintf("set bytes failed [%s]", err.Error()))
	}

	return &bls12_381G2{p}
}

func (c *Bls12_381) NewGtFromBytes(b []byte) driver.Gt {
	gt := bls12381.NewGT()
	p, err := gt.FromBytes(b)
	if err != nil {
		panic(fmt.Sprintf("set bytes failed [%s]", err.Error()))
	}

	return &bls12_381Gt{p}
}

func (c *Bls12_381) HashToZr(data []byte) driver.Zr {
	digest := sha256.Sum256(data)
	digestBig := c.NewZrFromBytes(digest[:])
	digestBig.Mod(c.GroupOrder())
	return digestBig
}

var domain = []byte("MATHLIB_BLS12381")

func (c *Bls12_381) HashToG1(data []byte) driver.G1 {
	g1 := bls12381.NewG1()
	p, err := g1.HashToCurve(data, domain)
	if err != nil {
		panic(fmt.Sprintf("HashToCurve failed [%s]", err.Error()))
	}

	return &bls12_381G1{p}
}

func (c *Bls12_381) NewRandomZr(rng io.Reader) driver.Zr {
	fr, err := bls12381.NewFr().Rand(rng)
	if err != nil {
		panic(err)
	}

	return &bls12_381Zr{fr}
}

func (c *Bls12_381) Rand() (io.Reader, error) {
	return rand.Reader, nil
}
