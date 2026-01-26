/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bls12381

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"math/big"
	"regexp"
	"strings"

	"github.com/IBM/mathlib/driver"
	"github.com/IBM/mathlib/driver/common"
	"github.com/IBM/mathlib/driver/gurvy"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"golang.org/x/crypto/blake2b"
)

var g1StrRegexp = regexp.MustCompile(`^E\([[]([0-9]+),([0-9]+)[]]\)$`)
var g1Bytes12_381 [48]byte
var g2Bytes12_381 [96]byte

// point at infinity
var g1Infinity bls12381.G1Jac

func init() {
	_, _, g1, g2 := bls12381.Generators()
	g1Bytes12_381 = g1.Bytes()
	g2Bytes12_381 = g2.Bytes()
	g1Infinity.X.SetOne()
	g1Infinity.Y.SetOne()
}

type Zr struct {
	big.Int
	Modulus big.Int
}

func (b *Zr) Plus(a driver.Zr) driver.Zr {
	rv := &Zr{Modulus: b.Modulus}
	rv.Add(&b.Int, &a.(*Zr).Int)
	return rv
}

func (b *Zr) Minus(a driver.Zr) driver.Zr {
	rv := &Zr{Modulus: b.Modulus}
	rv.Sub(&b.Int, &a.(*Zr).Int)
	return rv
}

func (b *Zr) Mul(a driver.Zr) driver.Zr {
	rv := &Zr{Modulus: b.Modulus}
	rv.Int.Mul(&b.Int, &a.(*Zr).Int)
	rv.Int.Mod(&rv.Int, &b.Modulus)
	return rv
}

func (b *Zr) PowMod(x driver.Zr) driver.Zr {
	fr := frElements.Get()
	defer frElements.Put(fr)

	fr.SetBigInt(&b.Int)
	fr.Exp(*fr, &x.(*Zr).Int)

	rv := &Zr{Modulus: b.Modulus}
	fr.BigInt(&rv.Int)
	return rv
}

func (b *Zr) Mod(a driver.Zr) {
	b.Int.Mod(&b.Int, &a.(*Zr).Int)
}

func (b *Zr) InvModP(p driver.Zr) {
	b.Int.ModInverse(&b.Int, &p.(*Zr).Int)
}

func (b *Zr) InvModOrder() {
	fr := frElements.Get()
	defer frElements.Put(fr)
	fr.SetBigInt(&b.Int)
	fr.Inverse(fr)
	fr.BigInt(&b.Int)
}

func (b *Zr) Bytes() []byte {
	target := b.Int

	if b.Int.Sign() < 0 || b.Int.Cmp(&b.Modulus) > 0 {
		target = *new(big.Int).Set(&b.Int)
		target = *target.Mod(&target, &b.Modulus)
		if target.Sign() < 0 {
			target = *target.Add(&target, &b.Modulus)
		}
	}

	return common.BigToBytes(&target)
}

func (b *Zr) Equals(p driver.Zr) bool {
	return b.Int.Cmp(&p.(*Zr).Int) == 0
}

func (b *Zr) Copy() driver.Zr {
	rv := &Zr{Modulus: b.Modulus}
	rv.Set(&b.Int)
	return rv
}

func (b *Zr) Clone(a driver.Zr) {
	raw := a.(*Zr).Int.Bytes()
	b.Int.SetBytes(raw)
}

func (b *Zr) String() string {
	return b.Int.Text(16)
}

func (b *Zr) Neg() {
	b.Int.Neg(&b.Int)
}

/*********************************************************************/

type G1 struct {
	bls12381.G1Affine
}

func (g *G1) Clone(a driver.G1) {
	raw := a.(*G1).G1Affine.Bytes()
	_, err := g.SetBytes(raw[:])
	if err != nil {
		panic("could not copy point")
	}
}

func (e *G1) Copy() driver.G1 {
	c := &G1{}
	c.Set(&e.G1Affine)
	return c
}

func (g *G1) Add(a driver.G1) {
	j := G1Jacs.Get()
	defer G1Jacs.Put(j)
	j.FromAffine(&g.G1Affine)
	j.AddMixed(&a.(*G1).G1Affine)
	g.G1Affine.FromJacobian(j)
}

func (g *G1) Mul(a driver.Zr) driver.G1 {
	gc := &G1{}
	gc.G1Affine.ScalarMultiplication(&g.G1Affine, &a.(*Zr).Int)

	return gc
}

func (g *G1) Mul2(e driver.Zr, Q driver.G1, f driver.Zr) driver.G1 {
	first := G1Jacs.Get()
	defer G1Jacs.Put(first)
	first = JointScalarMultiplication(first, &g.G1Affine, &Q.(*G1).G1Affine, &e.(*Zr).Int, &f.(*Zr).Int)
	gc := &G1{}
	gc.G1Affine.FromJacobian(first)
	return gc
}

func (g *G1) Mul2InPlace(e driver.Zr, Q driver.G1, f driver.Zr) {
	first := G1Jacs.Get()
	defer G1Jacs.Put(first)
	first = JointScalarMultiplication(first, &g.G1Affine, &Q.(*G1).G1Affine, &e.(*Zr).Int, &f.(*Zr).Int)
	g.G1Affine.FromJacobian(first)
}

func (g *G1) Equals(a driver.G1) bool {
	return g.G1Affine.Equal(&a.(*G1).G1Affine)
}

func (g *G1) Bytes() []byte {
	raw := g.G1Affine.RawBytes()
	return raw[:]
}

func (g *G1) Compressed() []byte {
	raw := g.G1Affine.Bytes()
	return raw[:]
}

func (g *G1) Sub(a driver.G1) {
	j, k := bls12381.G1Jac{}, bls12381.G1Jac{}
	j.FromAffine(&g.G1Affine)
	k.FromAffine(&a.(*G1).G1Affine)
	j.SubAssign(&k)
	g.G1Affine.FromJacobian(&j)
}

func (g *G1) IsInfinity() bool {
	return g.G1Affine.IsInfinity()
}

func (g *G1) String() string {
	rawstr := g.G1Affine.String()
	m := g1StrRegexp.FindAllStringSubmatch(rawstr, -1)
	return "(" + strings.TrimLeft(m[0][1], "0") + "," + strings.TrimLeft(m[0][2], "0") + ")"
}

func (g *G1) Neg() {
	g.G1Affine.Neg(&g.G1Affine)
}

/*********************************************************************/

type G2 struct {
	bls12381.G2Affine
}

func (g *G2) Clone(a driver.G2) {
	raw := a.(*G2).G2Affine.Bytes()
	_, err := g.SetBytes(raw[:])
	if err != nil {
		panic("could not copy point")
	}
}

func (e *G2) Copy() driver.G2 {
	c := &G2{}
	c.Set(&e.G2Affine)
	return c
}

func (g *G2) Mul(a driver.Zr) driver.G2 {
	gc := &G2{}
	gc.G2Affine.ScalarMultiplication(&g.G2Affine, &a.(*Zr).Int)

	return gc
}

func (g *G2) Add(a driver.G2) {
	j := bls12381.G2Jac{}
	j.FromAffine(&g.G2Affine)
	j.AddMixed((*bls12381.G2Affine)(&a.(*G2).G2Affine))
	g.G2Affine.FromJacobian(&j)
}

func (g *G2) Sub(a driver.G2) {
	j := bls12381.G2Jac{}
	j.FromAffine(&g.G2Affine)
	aJac := bls12381.G2Jac{}
	aJac.FromAffine((*bls12381.G2Affine)(&a.(*G2).G2Affine))
	j.SubAssign(&aJac)
	g.G2Affine.FromJacobian(&j)
}

func (g *G2) Affine() {
	// we're always affine
}

func (g *G2) Bytes() []byte {
	raw := g.G2Affine.RawBytes()
	return raw[:]
}

func (g *G2) Compressed() []byte {
	raw := g.G2Affine.Bytes()
	return raw[:]
}

func (g *G2) String() string {
	return g.G2Affine.String()
}

func (g *G2) Equals(a driver.G2) bool {
	return g.G2Affine.Equal(&a.(*G2).G2Affine)
}

/*********************************************************************/

type Gt struct {
	bls12381.GT
}

func (g *Gt) Exp(x driver.Zr) driver.Gt {
	c := bls12381.GT{}
	return &Gt{*c.Exp(g.GT, &x.(*Zr).Int)}
}

func (g *Gt) Equals(a driver.Gt) bool {
	return g.GT.Equal(&a.(*Gt).GT)
}

func (g *Gt) Inverse() {
	g.GT.Inverse(&g.GT)
}

func (g *Gt) Mul(a driver.Gt) {
	g.GT.Mul(&g.GT, &a.(*Gt).GT)
}

func (g *Gt) IsUnity() bool {
	unity := bls12381.GT{}
	unity.SetOne()

	return unity.Equal(&g.GT)
}

func (g *Gt) ToString() string {
	return g.GT.String()
}

func (g *Gt) Bytes() []byte {
	raw := g.GT.Bytes()
	return raw[:]
}

/*********************************************************************/

type Curve struct {
	common.CurveBase
}

func (c *Curve) MultiScalarMult(a []driver.G1, b []driver.Zr) driver.G1 {
	//TODO implement me
	return &G1{}
}

func NewCurve() *Curve {
	return &Curve{common.CurveBase{Modulus: *fr.Modulus()}}
}

func (c *Curve) Pairing(p2 driver.G2, p1 driver.G1) driver.Gt {
	t, err := bls12381.MillerLoop([]bls12381.G1Affine{p1.(*G1).G1Affine}, []bls12381.G2Affine{p2.(*G2).G2Affine})
	if err != nil {
		panic(fmt.Sprintf("pairing failed [%s]", err.Error()))
	}

	return &Gt{t}
}

func (c *Curve) Pairing2(p2a, p2b driver.G2, p1a, p1b driver.G1) driver.Gt {
	t, err := bls12381.MillerLoop([]bls12381.G1Affine{p1a.(*G1).G1Affine, p1b.(*G1).G1Affine}, []bls12381.G2Affine{p2a.(*G2).G2Affine, p2b.(*G2).G2Affine})
	if err != nil {
		panic(fmt.Sprintf("pairing 2 failed [%s]", err.Error()))
	}

	return &Gt{t}
}

func (c *Curve) FExp(a driver.Gt) driver.Gt {
	return &Gt{bls12381.FinalExponentiation(&a.(*Gt).GT)}
}

func (c *Curve) GenG1() driver.G1 {
	r := &G1{}
	_, err := r.SetBytes(g1Bytes12_381[:])
	if err != nil {
		panic("could not generate point")
	}

	return r
}

func (c *Curve) GenG2() driver.G2 {
	r := &G2{}
	_, err := r.SetBytes(g2Bytes12_381[:])
	if err != nil {
		panic("could not generate point")
	}

	return r
}

func (c *Curve) GenGt() driver.Gt {
	g1 := c.GenG1()
	g2 := c.GenG2()
	gengt := c.Pairing(g2, g1)
	gengt = c.FExp(gengt)
	return gengt
}

func (c *Curve) CoordinateByteSize() int {
	return bls12381.SizeOfG1AffineCompressed
}

func (c *Curve) G1ByteSize() int {
	return bls12381.SizeOfG1AffineUncompressed
}

func (c *Curve) CompressedG1ByteSize() int {
	return bls12381.SizeOfG1AffineCompressed
}

func (c *Curve) G2ByteSize() int {
	return bls12381.SizeOfG2AffineUncompressed
}

func (c *Curve) CompressedG2ByteSize() int {
	return bls12381.SizeOfG2AffineCompressed
}

func (c *Curve) ScalarByteSize() int {
	return common.ScalarByteSize
}

func (c *Curve) NewG1() driver.G1 {
	return &G1{}
}

func (c *Curve) NewG2() driver.G2 {
	return &G2{}
}

func (c *Curve) NewG1FromBytes(b []byte) driver.G1 {
	v := &G1{}
	_, err := v.G1Affine.SetBytes(b)
	if err != nil {
		panic(fmt.Sprintf("set bytes failed [%s]", err.Error()))
	}

	return v
}

func (c *Curve) NewG2FromBytes(b []byte) driver.G2 {
	v := &G2{}
	_, err := v.SetBytes(b)
	if err != nil {
		panic(fmt.Sprintf("set bytes failed [%s]", err.Error()))
	}

	return v
}

func (c *Curve) NewG1FromCompressed(b []byte) driver.G1 {
	v := &G1{}
	_, err := v.SetBytes(b)
	if err != nil {
		panic(fmt.Sprintf("set bytes failed [%s]", err.Error()))
	}

	return v
}

func (c *Curve) NewG2FromCompressed(b []byte) driver.G2 {
	v := &G2{}
	_, err := v.SetBytes(b)
	if err != nil {
		panic(fmt.Sprintf("set bytes failed [%s]", err.Error()))
	}

	return v
}

func (c *Curve) NewGtFromBytes(b []byte) driver.Gt {
	v := &Gt{}
	err := v.SetBytes(b)
	if err != nil {
		panic(fmt.Sprintf("set bytes failed [%s]", err.Error()))
	}

	return v
}

func (c *Curve) ModNeg(a1, m driver.Zr) driver.Zr {
	res := &Zr{Modulus: c.Modulus}
	res.Int.Sub(&m.(*Zr).Int, &a1.(*Zr).Int)
	res.Int.Mod(&res.Int, &m.(*Zr).Int)

	return res
}

func (c *Curve) ModSub(a1, b1, m driver.Zr) driver.Zr {
	a1Fr := frElements.Get()
	defer frElements.Put(a1Fr)
	a1Fr.SetBigInt(&a1.(*Zr).Int)

	a2Fr := frElements.Get()
	defer frElements.Put(a2Fr)
	a2Fr.SetBigInt(&b1.(*Zr).Int)

	a1Fr.Sub(a1Fr, a2Fr)

	res := &Zr{Modulus: c.Modulus}
	a1Fr.BigInt(&res.Int)
	return res
}

func (c *Curve) GroupOrder() driver.Zr {
	return &Zr{Int: c.Modulus, Modulus: c.Modulus}
}

func (c *Curve) NewZrFromBytes(b []byte) driver.Zr {
	res := &Zr{Modulus: c.Modulus}
	res.Int.SetBytes(b)
	return res
}

func (c *Curve) NewZrFromInt64(i int64) driver.Zr {
	return &Zr{Int: *big.NewInt(i), Modulus: c.Modulus}
}

func (c *Curve) NewZrFromUint64(i uint64) driver.Zr {
	return &Zr{Int: *new(big.Int).SetUint64(i), Modulus: c.Modulus}
}

func (c *Curve) NewRandomZr(rng io.Reader) driver.Zr {
	bi, err := rand.Int(rng, &c.Modulus)
	if err != nil {
		panic(err)
	}

	return &Zr{Int: *bi, Modulus: c.Modulus}
}

func (c *Curve) HashToZr(data []byte) driver.Zr {
	digest := sha256.Sum256(data)
	digestBig := new(big.Int).SetBytes(digest[:])
	digestBig.Mod(digestBig, &c.Modulus)
	return &Zr{Int: *digestBig, Modulus: c.Modulus}
}

func (p *Curve) Rand() (io.Reader, error) {
	return rand.Reader, nil
}

func (c *Curve) HashToG1(data []byte) driver.G1 {
	g1, err := bls12381.HashToG1(data, []byte{})
	if err != nil {
		panic(fmt.Sprintf("HashToG1 failed [%s]", err.Error()))
	}

	return &G1{g1}
}

func (c *Curve) HashToG2(data []byte) driver.G2 {
	g2, err := bls12381.HashToG2(data, []byte{})
	if err != nil {
		panic(fmt.Sprintf("HashToG2 failed [%s]", err.Error()))
	}

	return &G2{g2}
}

func (c *Curve) HashToG1WithDomain(data, domain []byte) driver.G1 {
	g1, err := bls12381.HashToG1(data, domain)
	if err != nil {
		panic(fmt.Sprintf("HashToG1 failed [%s]", err.Error()))
	}

	return &G1{g1}
}

func (c *Curve) HashToG2WithDomain(data, domain []byte) driver.G2 {
	g2, err := bls12381.HashToG2(data, domain)
	if err != nil {
		panic(fmt.Sprintf("HashToG2 failed [%s]", err.Error()))
	}

	return &G2{g2}
}

func (c *Curve) ModMul(a1, b1, m driver.Zr) driver.Zr {
	a1Fr := frElements.Get()
	defer frElements.Put(a1Fr)
	a1Fr.SetBigInt(&a1.(*Zr).Int)

	a2Fr := frElements.Get()
	defer frElements.Put(a2Fr)
	a2Fr.SetBigInt(&b1.(*Zr).Int)

	a1Fr.Mul(a1Fr, a2Fr)

	res := &Zr{Modulus: c.Modulus}
	a1Fr.BigInt(&res.Int)
	return res
}

func (c *Curve) ModAddMul(a1, b1 []driver.Zr, m driver.Zr) driver.Zr {
	a1Fr := frElements.Get()
	defer frElements.Put(a1Fr)
	b1Fr := frElements.Get()
	defer frElements.Put(b1Fr)
	sum := frElements.Get()
	defer frElements.Put(sum)

	sum.SetZero()
	for i := 0; i < len(a1); i++ {
		a1Fr.SetBigInt(&a1[i].(*Zr).Int)
		b1Fr.SetBigInt(&b1[i].(*Zr).Int)
		a1Fr.Mul(a1Fr, b1Fr)
		sum.Add(sum, a1Fr)
	}

	res := &Zr{Modulus: c.Modulus}
	sum.BigInt(&res.Int)
	return res
}

func (c *Curve) ModAddMul2(a1 driver.Zr, c1 driver.Zr, b1 driver.Zr, c2 driver.Zr, m driver.Zr) driver.Zr {
	aFr := frElements.Get()
	defer frElements.Put(aFr)
	cFr := frElements.Get()
	defer frElements.Put(cFr)

	sum := frElements.Get()
	defer frElements.Put(sum)

	sum.SetZero()
	aFr.SetBigInt(&a1.(*Zr).Int)
	cFr.SetBigInt(&c1.(*Zr).Int)
	aFr.Mul(aFr, cFr)
	sum.Add(sum, aFr)

	aFr.SetBigInt(&b1.(*Zr).Int)
	cFr.SetBigInt(&c2.(*Zr).Int)
	aFr.Mul(aFr, cFr)
	sum.Add(sum, aFr)

	res := &Zr{Modulus: c.Modulus}
	sum.BigInt(&res.Int)
	return res
}

func (c *Curve) ModAdd(a1, b1, m driver.Zr) driver.Zr {
	a1Fr := frElements.Get()
	defer frElements.Put(a1Fr)
	a1Fr.SetBigInt(&a1.(*Zr).Int)

	a2Fr := frElements.Get()
	defer frElements.Put(a2Fr)
	a2Fr.SetBigInt(&b1.(*Zr).Int)

	a1Fr.Add(a1Fr, a2Fr)

	res := &Zr{Modulus: c.Modulus}
	a1Fr.BigInt(&res.Int)
	return res
}

func (c *Curve) ModAdd2(a1, b1, c1, m driver.Zr) {
	a1Fr := frElements.Get()
	defer frElements.Put(a1Fr)
	a1Fr.SetBigInt(&a1.(*Zr).Int)

	tmp := frElements.Get()
	defer frElements.Put(tmp)
	tmp.SetBigInt(&b1.(*Zr).Int)

	a1Fr.Add(a1Fr, tmp)

	tmp.SetBigInt(&c1.(*Zr).Int)
	a1Fr.Add(a1Fr, tmp)

	a1Fr.BigInt(&a1.(*Zr).Int)
}

type BBSCurve struct {
	Curve
}

func (c *BBSCurve) MultiScalarMult(a []driver.G1, b []driver.Zr) driver.G1 {
	//TODO implement me
	return &G1{}
}

func NewBBSCurve() *BBSCurve {
	return &BBSCurve{*NewCurve()}
}

func (c *BBSCurve) HashToG1(data []byte) driver.G1 {
	hashFunc := func() hash.Hash {
		// We pass a null key so error is impossible here.
		h, _ := blake2b.New512(nil) //nolint:errcheck
		return h
	}

	g1, err := gurvy.HashToG1GenericBESwu(data, []byte{}, hashFunc)
	if err != nil {
		panic(fmt.Sprintf("HashToG1 failed [%s]", err.Error()))
	}

	return &G1{g1}
}

func (c *BBSCurve) HashToG2(data []byte) driver.G2 {
	g2, err := bls12381.HashToG2(data, []byte{})
	if err != nil {
		panic(fmt.Sprintf("HashToG2 failed [%s]", err.Error()))
	}

	return &G2{g2}
}

func (c *BBSCurve) HashToG1WithDomain(data, domain []byte) driver.G1 {
	hashFunc := func() hash.Hash {
		// We pass a null key so error is impossible here.
		h, _ := blake2b.New512(nil) //nolint:errcheck
		return h
	}

	g1, err := gurvy.HashToG1GenericBESwu(data, domain, hashFunc)
	if err != nil {
		panic(fmt.Sprintf("HashToG1 failed [%s]", err.Error()))
	}

	return &G1{g1}
}

func (c *BBSCurve) HashToG2WithDomain(data, domain []byte) driver.G2 {
	g2, err := bls12381.HashToG2(data, domain)
	if err != nil {
		panic(fmt.Sprintf("HashToG2 failed [%s]", err.Error()))
	}

	return &G2{g2}
}

// JointScalarMultiplication computes [s1]a1+[s2]a2 using Strauss-Shamir technique
// where a1 and a2 are affine points.
func JointScalarMultiplication(p *bls12381.G1Jac, a1, a2 *bls12381.G1Affine, s1, s2 *big.Int) *bls12381.G1Jac {
	var res, p1, p2 bls12381.G1Jac
	res.Set(&g1Infinity)
	p1.FromAffine(a1)
	p2.FromAffine(a2)

	var table [15]bls12381.G1Jac

	var k1, k2 big.Int
	if s1.Sign() == -1 {
		k1.Neg(s1)
		table[0].Neg(&p1)
	} else {
		k1 = *s1
		table[0].Set(&p1)
	}
	if s2.Sign() == -1 {
		k2.Neg(s2)
		table[3].Neg(&p2)
	} else {
		k2 = *s2
		table[3].Set(&p2)
	}

	// precompute table (2 bits sliding window)
	table[1].Double(&table[0])
	table[2].Set(&table[1]).AddAssign(&table[0])
	table[4].Set(&table[3]).AddAssign(&table[0])
	table[5].Set(&table[3]).AddAssign(&table[1])
	table[6].Set(&table[3]).AddAssign(&table[2])
	table[7].Double(&table[3])
	table[8].Set(&table[7]).AddAssign(&table[0])
	table[9].Set(&table[7]).AddAssign(&table[1])
	table[10].Set(&table[7]).AddAssign(&table[2])
	table[11].Set(&table[7]).AddAssign(&table[3])
	table[12].Set(&table[11]).AddAssign(&table[0])
	table[13].Set(&table[11]).AddAssign(&table[1])
	table[14].Set(&table[11]).AddAssign(&table[2])

	var s [2]fr.Element
	s[0] = s[0].SetBigInt(&k1).Bits()
	s[1] = s[1].SetBigInt(&k2).Bits()

	maxBit := k1.BitLen()
	if k2.BitLen() > maxBit {
		maxBit = k2.BitLen()
	}
	hiWordIndex := (maxBit - 1) / 64

	for i := hiWordIndex; i >= 0; i-- {
		mask := uint64(3) << 62
		for j := 0; j < 32; j++ {
			res.Double(&res).Double(&res)
			b1 := (s[0][i] & mask) >> (62 - 2*j)
			b2 := (s[1][i] & mask) >> (62 - 2*j)
			if b1|b2 != 0 {
				s := (b2<<2 | b1)
				res.AddAssign(&table[s-1])
			}
			mask = mask >> 2
		}
	}

	p.Set(&res)
	return p

}
