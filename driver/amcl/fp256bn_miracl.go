/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package amcl

import (
	r "crypto/rand"
	"crypto/sha256"
	"io"
	"math/big"
	"strings"

	"github.com/IBM/mathlib/driver"
	"github.com/IBM/mathlib/driver/common"
	"github.com/hyperledger/fabric-amcl/core/FP256BN"
)

/*********************************************************************/

var modulusBig big.Int // q stored as big.Int
func init() {
	modulusBig.SetString("fffffffffffcf0cd46e5f25eee71a49e0cdc65fb1299921af62d536cd10b500d", 16)
}

type fp256bnMiraclZr struct {
	*big.Int
}

func (b *fp256bnMiraclZr) Plus(a driver.Zr) driver.Zr {
	return &fp256bnMiraclZr{new(big.Int).Add(b.Int, a.(*fp256bnMiraclZr).Int)}
}

func (b *fp256bnMiraclZr) Minus(a driver.Zr) driver.Zr {
	return &fp256bnMiraclZr{new(big.Int).Sub(b.Int, a.(*fp256bnMiraclZr).Int)}
}

func (b *fp256bnMiraclZr) Mul(a driver.Zr) driver.Zr {
	prod := new(big.Int).Mul(b.Int, a.(*fp256bnMiraclZr).Int)
	return &fp256bnMiraclZr{prod.Mod(prod, &modulusBig)}
}

func (b *fp256bnMiraclZr) PowMod(x driver.Zr) driver.Zr {
	return &fp256bnMiraclZr{new(big.Int).Exp(b.Int, x.(*fp256bnMiraclZr).Int, &modulusBig)}
}

func (b *fp256bnMiraclZr) Mod(a driver.Zr) {
	b.Int.Mod(b.Int, a.(*fp256bnMiraclZr).Int)
}

func (b *fp256bnMiraclZr) InvModP(p driver.Zr) {
	b.Int.ModInverse(b.Int, p.(*fp256bnMiraclZr).Int)
}

func (b *fp256bnMiraclZr) Bytes() []byte {
	target := b.Int

	if b.Int.Sign() < 0 || b.Int.Cmp(&modulusBig) > 0 {
		target = new(big.Int).Set(b.Int)
		target = target.Mod(target, &modulusBig)
		if target.Sign() < 0 {
			target = target.Add(target, &modulusBig)
		}
	}

	return common.BigToBytes(target)
}

func (b *fp256bnMiraclZr) Equals(p driver.Zr) bool {
	return b.Int.Cmp(p.(*fp256bnMiraclZr).Int) == 0
}

func (b *fp256bnMiraclZr) Copy() driver.Zr {
	return &fp256bnMiraclZr{new(big.Int).Set(b.Int)}
}

func (b *fp256bnMiraclZr) Clone(a driver.Zr) {
	raw := a.(*fp256bnMiraclZr).Int.Bytes()
	b.Int.SetBytes(raw)
}

func (b *fp256bnMiraclZr) String() string {
	return b.Int.Text(16)
}

func (b *fp256bnMiraclZr) Neg() {
	b.Int.Neg(b.Int)
}

/*********************************************************************/

type fp256bnMiraclGt struct {
	*FP256BN.FP12
}

func (a *fp256bnMiraclGt) Exp(x driver.Zr) driver.Gt {
	return &fp256bnMiraclGt{a.FP12.Pow(bigToMiraclBIG(x.(*fp256bnMiraclZr).Int))}
}

func (a *fp256bnMiraclGt) Equals(b driver.Gt) bool {
	return a.FP12.Equals(b.(*fp256bnMiraclGt).FP12)
}

func (a *fp256bnMiraclGt) IsUnity() bool {
	return a.FP12.Isunity()
}

func (a *fp256bnMiraclGt) Inverse() {
	a.FP12.Inverse()
}

func (a *fp256bnMiraclGt) Mul(b driver.Gt) {
	a.FP12.Mul(b.(*fp256bnMiraclGt).FP12)
}

func (b *fp256bnMiraclGt) ToString() string {
	return b.FP12.ToString()
}

func (b *fp256bnMiraclGt) Bytes() []byte {
	bytes := make([]byte, 12*int(FP256BN.MODBYTES))
	b.FP12.ToBytes(bytes)
	return bytes
}

/*********************************************************************/

type Fp256Miraclbn struct {
}

func (*Fp256Miraclbn) Pairing(a driver.G2, b driver.G1) driver.Gt {
	return &fp256bnMiraclGt{FP256BN.Ate(a.(*fp256bnMiraclG2).ECP2, b.(*fp256bnMiraclG1).ECP)}
}

func (*Fp256Miraclbn) Pairing2(p2a, p2b driver.G2, p1a, p1b driver.G1) driver.Gt {
	return &fp256bnMiraclGt{FP256BN.Ate2(p2a.(*fp256bnMiraclG2).ECP2, p1a.(*fp256bnMiraclG1).ECP, p2b.(*fp256bnMiraclG2).ECP2, p1b.(*fp256bnMiraclG1).ECP)}
}

func (*Fp256Miraclbn) FExp(e driver.Gt) driver.Gt {
	return &fp256bnMiraclGt{FP256BN.Fexp(e.(*fp256bnMiraclGt).FP12)}
}

func (*Fp256Miraclbn) ModMul(a1, b1, m driver.Zr) driver.Zr {
	res := a1.Mul(b1)
	res.Mod(m)
	return res
}

func (*Fp256Miraclbn) ModNeg(a1, m driver.Zr) driver.Zr {
	res := new(big.Int).Sub(m.(*fp256bnMiraclZr).Int, a1.(*fp256bnMiraclZr).Int)
	if res.Sign() < 0 {
		res = res.Add(res, &modulusBig)
	}
	return &fp256bnMiraclZr{res}
}

func (*Fp256Miraclbn) GenG1() driver.G1 {
	return &fp256bnMiraclG1{FP256BN.NewECPbigs(FP256BN.NewBIGints(FP256BN.CURVE_Gx), FP256BN.NewBIGints(FP256BN.CURVE_Gy))}
}

func (*Fp256Miraclbn) GenG2() driver.G2 {
	return &fp256bnMiraclG2{FP256BN.NewECP2fp2s(
		FP256BN.NewFP2bigs(FP256BN.NewBIGints(FP256BN.CURVE_Pxa), FP256BN.NewBIGints(FP256BN.CURVE_Pxb)),
		FP256BN.NewFP2bigs(FP256BN.NewBIGints(FP256BN.CURVE_Pya), FP256BN.NewBIGints(FP256BN.CURVE_Pyb)))}
}

func (p *Fp256Miraclbn) GenGt() driver.Gt {
	return &fp256bnMiraclGt{FP256BN.Fexp(FP256BN.Ate(p.GenG2().(*fp256bnMiraclG2).ECP2, p.GenG1().(*fp256bnMiraclG1).ECP))}
}

func (p *Fp256Miraclbn) GroupOrder() driver.Zr {
	return &fp256bnMiraclZr{&modulusBig}
}

func (p *Fp256Miraclbn) CoordinateByteSize() int {
	return int(FP256BN.MODBYTES)
}
func (p *Fp256Miraclbn) ScalarByteSize() int {
	return int(FP256BN.MODBYTES)
}

func (p *Fp256Miraclbn) NewG1() driver.G1 {
	return &fp256bnMiraclG1{FP256BN.NewECP()}
}

func (p *Fp256Miraclbn) NewG2() driver.G2 {
	return &fp256bnMiraclG2{FP256BN.NewECP2()}
}

func (p *Fp256Miraclbn) NewG1FromCoords(ix, iy driver.Zr) driver.G1 {
	return nil
}

func (p *Fp256Miraclbn) NewZrFromBytes(b []byte) driver.Zr {
	return &fp256bnMiraclZr{new(big.Int).SetBytes(b)}
}

func bigToMiraclBIG(bi *big.Int) *FP256BN.BIG {
	var i0, i1, i2, i3, i4 int64
	biCopy := bi

	if bi.Sign() < 0 || bi.Cmp(&modulusBig) > 0 {
		biCopy = new(big.Int).Set(bi)
		biCopy = biCopy.Mod(biCopy, &modulusBig)
		if biCopy.Sign() < 0 {
			biCopy = biCopy.Add(biCopy, &modulusBig)
		}
	}

	b := common.BigToBytes(biCopy)

	pos := 32
	i0 = new(big.Int).SetBytes(b[pos-7 : pos]).Int64()
	pos -= 7
	i1 = new(big.Int).SetBytes(b[pos-7 : pos]).Int64()
	pos -= 7
	i2 = new(big.Int).SetBytes(b[pos-7 : pos]).Int64()
	pos -= 7
	i3 = new(big.Int).SetBytes(b[pos-7 : pos]).Int64()
	pos -= 7
	i4 = new(big.Int).SetBytes(b[0:pos]).Int64()

	zr := FP256BN.NewBIGints([FP256BN.NLEN]FP256BN.Chunk{FP256BN.Chunk(i0), FP256BN.Chunk(i1), FP256BN.Chunk(i2), FP256BN.Chunk(i3), FP256BN.Chunk(i4)})

	return zr
}

func (p *Fp256Miraclbn) NewZrFromInt(i int64) driver.Zr {
	return &fp256bnMiraclZr{big.NewInt(i)}
}

func (p *Fp256Miraclbn) NewG1FromBytes(b []byte) driver.G1 {
	return &fp256bnMiraclG1{FP256BN.ECP_fromBytes(b)}
}

func (p *Fp256Miraclbn) NewG2FromBytes(b []byte) driver.G2 {
	return &fp256bnMiraclG2{FP256BN.ECP2_fromBytes(b)}
}

func (p *Fp256Miraclbn) NewG1FromCompressed(b []byte) driver.G1 {
	return &fp256bnMiraclG1{FP256BN.ECP_fromBytes(b)}
}

func (p *Fp256Miraclbn) NewG2FromCompressed(b []byte) driver.G2 {
	return &fp256bnMiraclG2{FP256BN.ECP2_fromBytes(b)}
}

func (p *Fp256Miraclbn) NewGtFromBytes(b []byte) driver.Gt {
	return &fp256bnMiraclGt{FP256BN.FP12_fromBytes(b)}
}

func (p *Fp256Miraclbn) ModAdd(a, b, m driver.Zr) driver.Zr {
	c := a.Plus(b)
	c.Mod(m)
	return c
}

func (p *Fp256Miraclbn) ModSub(a, b, m driver.Zr) driver.Zr {
	return p.ModAdd(a, p.ModNeg(b, m), m)
}

func (p *Fp256Miraclbn) HashToZr(data []byte) driver.Zr {
	digest := sha256.Sum256(data)
	digestBig := p.NewZrFromBytes(digest[:])
	digestBig.Mod(p.GroupOrder())
	return digestBig
}

func (p *Fp256Miraclbn) HashToG1(data []byte) driver.G1 {
	zr := p.HashToZr(data)
	fp := FP256BN.NewFPbig(bigToMiraclBIG(zr.(*fp256bnMiraclZr).Int))
	return &fp256bnMiraclG1{FP256BN.ECP_map2point(fp)}
}

func (p *Fp256Miraclbn) Rand() (io.Reader, error) {
	return r.Reader, nil
}

func (p *Fp256Miraclbn) NewRandomZr(rng io.Reader) driver.Zr {
	bi, err := r.Int(rng, &modulusBig)
	if err != nil {
		panic(err)
	}

	return &fp256bnMiraclZr{bi}
}

/*********************************************************************/

type fp256bnMiraclG1 struct {
	*FP256BN.ECP
}

func (e *fp256bnMiraclG1) Clone(a driver.G1) {
	e.ECP.Copy(a.(*fp256bnMiraclG1).ECP)
}

func (e *fp256bnMiraclG1) Copy() driver.G1 {
	c := FP256BN.NewECP()
	c.Copy(e.ECP)
	return &fp256bnMiraclG1{c}
}

func (e *fp256bnMiraclG1) Add(a driver.G1) {
	e.ECP.Add(a.(*fp256bnMiraclG1).ECP)
}

func (e *fp256bnMiraclG1) Mul(a driver.Zr) driver.G1 {
	return &fp256bnMiraclG1{FP256BN.G1mul(e.ECP, bigToMiraclBIG(a.(*fp256bnMiraclZr).Int))}
}

func (e *fp256bnMiraclG1) Mul2(ee driver.Zr, Q driver.G1, f driver.Zr) driver.G1 {
	return &fp256bnMiraclG1{e.ECP.Mul2(bigToMiraclBIG(ee.(*fp256bnMiraclZr).Int), Q.(*fp256bnMiraclG1).ECP, bigToMiraclBIG(f.(*fp256bnMiraclZr).Int))}
}

func (e *fp256bnMiraclG1) Equals(a driver.G1) bool {
	return e.ECP.Equals(a.(*fp256bnMiraclG1).ECP)
}

func (e *fp256bnMiraclG1) IsInfinity() bool {
	return e.ECP.Is_infinity()
}

func (e *fp256bnMiraclG1) Bytes() []byte {
	b := make([]byte, 2*int(FP256BN.MODBYTES)+1)
	e.ECP.ToBytes(b, false)
	return b
}

func (e *fp256bnMiraclG1) Compressed() []byte {
	b := make([]byte, int(FP256BN.MODBYTES)+1)
	e.ECP.ToBytes(b, true)
	return b
}

func (e *fp256bnMiraclG1) Sub(a driver.G1) {
	e.ECP.Sub(a.(*fp256bnMiraclG1).ECP)
}

func (b *fp256bnMiraclG1) String() string {
	rawstr := b.ECP.ToString()
	m := g1StrRegexp.FindAllStringSubmatch(rawstr, -1)
	return "(" + strings.TrimLeft(m[0][1], "0") + "," + strings.TrimLeft(m[0][2], "0") + ")"
}

func (e *fp256bnMiraclG1) Neg() {
	e.ECP.Neg()
}

/*********************************************************************/

type fp256bnMiraclG2 struct {
	*FP256BN.ECP2
}

func (e *fp256bnMiraclG2) Equals(a driver.G2) bool {
	return e.ECP2.Equals(a.(*fp256bnMiraclG2).ECP2)
}

func (e *fp256bnMiraclG2) Clone(a driver.G2) {
	e.ECP2.Copy(a.(*fp256bnMiraclG2).ECP2)
}

func (e *fp256bnMiraclG2) Copy() driver.G2 {
	c := FP256BN.NewECP2()
	c.Copy(e.ECP2)
	return &fp256bnMiraclG2{c}
}

func (e *fp256bnMiraclG2) Add(a driver.G2) {
	e.ECP2.Add(a.(*fp256bnMiraclG2).ECP2)
}

func (e *fp256bnMiraclG2) Sub(a driver.G2) {
	e.ECP2.Sub(a.(*fp256bnMiraclG2).ECP2)
}

func (e *fp256bnMiraclG2) Mul(a driver.Zr) driver.G2 {
	return &fp256bnMiraclG2{e.ECP2.Mul(bigToMiraclBIG(a.(*fp256bnMiraclZr).Int))}
}

func (e *fp256bnMiraclG2) Affine() {
	e.ECP2.Affine()
}

func (e *fp256bnMiraclG2) Bytes() []byte {
	b := make([]byte, 4*int(FP256BN.MODBYTES)+1)
	e.ECP2.ToBytes(b, false)
	return b
}

func (e *fp256bnMiraclG2) Compressed() []byte {
	b := make([]byte, 2*int(FP256BN.MODBYTES)+1)
	e.ECP2.ToBytes(b, true)
	return b
}

func (b *fp256bnMiraclG2) String() string {
	return b.ECP2.ToString()
}
