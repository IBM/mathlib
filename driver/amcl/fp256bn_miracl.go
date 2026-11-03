/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package amcl

import (
	"bytes"
	"fmt"
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

/*********************************************************************/

type fp256bnMiraclGt struct {
	FP256BN.FP12
}

func (a *fp256bnMiraclGt) Exp(x driver.Zr) driver.Gt {
	return &fp256bnMiraclGt{*a.Pow(bigToMiraclBIG(&x.(*common.BaseZr).Int))}
}

func (a *fp256bnMiraclGt) Equals(b driver.Gt) bool {
	return a.FP12.Equals(&b.(*fp256bnMiraclGt).FP12)
}

func (a *fp256bnMiraclGt) IsUnity() bool {
	return a.Isunity()
}

func (a *fp256bnMiraclGt) Inverse() {
	a.FP12.Inverse()
}

func (a *fp256bnMiraclGt) Mul(b driver.Gt) {
	a.FP12.Mul(&b.(*fp256bnMiraclGt).FP12)
}

func (b *fp256bnMiraclGt) ToString() string {
	return b.FP12.ToString()
}

func (b *fp256bnMiraclGt) Bytes() []byte {
	bytes := make([]byte, 12*int(FP256BN.MODBYTES))
	b.ToBytes(bytes)

	return bytes
}

/*********************************************************************/

func NewFp256Miraclbn() *Fp256Miraclbn {
	return &Fp256Miraclbn{common.CurveBase{Modulus: modulusBig}}
}

type Fp256Miraclbn struct {
	common.CurveBase
}

func (p *Fp256Miraclbn) MultiScalarMul(a []driver.G1, b []driver.Zr) driver.G1 {
	g1 := p.NewG1()
	for i := range a {
		g1.Add(a[i].Mul(b[i]))
	}

	return g1
}

func (*Fp256Miraclbn) Pairing(a driver.G2, b driver.G1) driver.Gt {
	return &fp256bnMiraclGt{*FP256BN.Ate(a.(*fp256bnMiraclG2).ECP2, &b.(*fp256bnMiraclG1).ECP)}
}

func (*Fp256Miraclbn) Pairing2(p2a, p2b driver.G2, p1a, p1b driver.G1) driver.Gt {
	return &fp256bnMiraclGt{*FP256BN.Ate2(p2a.(*fp256bnMiraclG2).ECP2, &p1a.(*fp256bnMiraclG1).ECP, p2b.(*fp256bnMiraclG2).ECP2, &p1b.(*fp256bnMiraclG1).ECP)}
}

func (*Fp256Miraclbn) FExp(e driver.Gt) driver.Gt {
	return &fp256bnMiraclGt{*FP256BN.Fexp(&e.(*fp256bnMiraclGt).FP12)}
}

func (*Fp256Miraclbn) GenG1() driver.G1 {
	return &fp256bnMiraclG1{*FP256BN.NewECPbigs(FP256BN.NewBIGints(FP256BN.CURVE_Gx), FP256BN.NewBIGints(FP256BN.CURVE_Gy))}
}

func (*Fp256Miraclbn) GenG2() driver.G2 {
	return &fp256bnMiraclG2{FP256BN.NewECP2fp2s(
		FP256BN.NewFP2bigs(FP256BN.NewBIGints(FP256BN.CURVE_Pxa), FP256BN.NewBIGints(FP256BN.CURVE_Pxb)),
		FP256BN.NewFP2bigs(FP256BN.NewBIGints(FP256BN.CURVE_Pya), FP256BN.NewBIGints(FP256BN.CURVE_Pyb)))}
}

func (p *Fp256Miraclbn) GenGt() driver.Gt {
	return &fp256bnMiraclGt{*FP256BN.Fexp(FP256BN.Ate(p.GenG2().(*fp256bnMiraclG2).ECP2, &p.GenG1().(*fp256bnMiraclG1).ECP))}
}

func (p *Fp256Miraclbn) CoordinateByteSize() int {
	return int(FP256BN.MODBYTES)
}

func (p *Fp256Miraclbn) G1ByteSize() int {
	return 2*int(FP256BN.MODBYTES) + 1
}

func (p *Fp256Miraclbn) CompressedG1ByteSize() int {
	return int(FP256BN.MODBYTES) + 1
}

func (p *Fp256Miraclbn) G2ByteSize() int {
	return 4*int(FP256BN.MODBYTES) + 1
}

func (p *Fp256Miraclbn) CompressedG2ByteSize() int {
	return 2*int(FP256BN.MODBYTES) + 1
}

func (p *Fp256Miraclbn) ScalarByteSize() int {
	return common.ScalarByteSize
}

func (p *Fp256Miraclbn) NewG1() driver.G1 {
	return &fp256bnMiraclG1{*FP256BN.NewECP()}
}

func (p *Fp256Miraclbn) NewG2() driver.G2 {
	return &fp256bnMiraclG2{FP256BN.NewECP2()}
}

func bigToMiraclBIG(bi *big.Int) *FP256BN.BIG {
	biCopy := bi

	// The group order itself is passed through unreduced: callers rely on
	// P.Mul(GroupOrder) (and Gt.Exp(GroupOrder)) to test subgroup membership,
	// which reducing q to 0 would turn into a check that always succeeds.
	if bi.Sign() < 0 || bi.Cmp(&modulusBig) > 0 {
		// big.Int.Mod is Euclidean: the result is always in [0, modulus).
		biCopy = new(big.Int).Mod(bi, &modulusBig)
	}

	return FP256BN.FromBytes(common.BigToBytes(biCopy))
}

// decodeFp256bnMiraclG1 decodes a G1 point from its uncompressed (0x04||X||Y)
// or compressed ((0x02|0x03)||X) encoding. See decodeFp256bnG1: ECP_fromBytes
// maps every invalid input to infinity and ignores trailing bytes, so we
// enforce exact length, prefix and a canonical round trip. G1 has cofactor 1.
func decodeFp256bnMiraclG1(b []byte, compressed bool) *FP256BN.ECP {
	size := 2*int(FP256BN.MODBYTES) + 1
	if compressed {
		size = int(FP256BN.MODBYTES) + 1
	}
	if len(b) != size {
		panic(fmt.Sprintf("invalid G1 encoding: expected %d bytes, got %d", size, len(b)))
	}
	if compressed && b[0] != 0x02 && b[0] != 0x03 || !compressed && b[0] != 0x04 {
		panic(fmt.Sprintf("invalid G1 encoding: unexpected prefix 0x%02x", b[0]))
	}

	P := FP256BN.ECP_fromBytes(b)

	re := make([]byte, size)
	P.ToBytes(re, compressed)
	if !bytes.Equal(re, b) {
		panic("invalid G1 encoding: not the canonical encoding of a point on the curve")
	}

	return P
}

// decodeFp256bnMiraclG2 decodes a G2 point from its uncompressed (0x04||X||Y)
// or compressed ((0x02|0x03)||X) encoding, enforcing exact length, prefix, a
// canonical round trip and membership in the order-r subgroup.
func decodeFp256bnMiraclG2(b []byte, compressed bool) *FP256BN.ECP2 {
	size := 4*int(FP256BN.MODBYTES) + 1
	if compressed {
		size = 2*int(FP256BN.MODBYTES) + 1
	}
	if len(b) != size {
		panic(fmt.Sprintf("invalid G2 encoding: expected %d bytes, got %d", size, len(b)))
	}
	if compressed && b[0] != 0x02 && b[0] != 0x03 || !compressed && b[0] != 0x04 {
		panic(fmt.Sprintf("invalid G2 encoding: unexpected prefix 0x%02x", b[0]))
	}

	P := FP256BN.ECP2_fromBytes(b)

	re := make([]byte, size)
	P.ToBytes(re, compressed)
	if !bytes.Equal(re, b) {
		panic("invalid G2 encoding: not the canonical encoding of a point on the twist")
	}

	// G2member returns false for the point at infinity, which is a valid G2 element.
	if !P.Is_infinity() && !FP256BN.G2member(P) {
		panic("invalid G2 encoding: point is not in the order-r subgroup")
	}

	return P
}

// isFp256bnG2Member reports whether the point encoded in b (MIRACL core
// uncompressed layout) is on the twist and in the order-r subgroup G2.
func isFp256bnG2Member(b []byte) bool {
	P := FP256BN.ECP2_fromBytes(b)

	return !P.Is_infinity() && FP256BN.G2member(P)
}

// isFp256bnGtMember reports whether the Fp12 element encoded in b (MIRACL core
// layout) is in the order-r subgroup Gt. The identity is a member (GTmember
// itself rejects it).
func isFp256bnGtMember(b []byte) bool {
	g := FP256BN.FP12_fromBytes(b)

	return g.Isunity() || FP256BN.GTmember(g)
}

// decodeFp256bnMiraclGt decodes a Gt element, requiring exact length,
// canonical field elements and membership in the order-r subgroup of Fp12^*.
func decodeFp256bnMiraclGt(b []byte) *FP256BN.FP12 {
	size := 12 * int(FP256BN.MODBYTES)
	if len(b) != size {
		panic(fmt.Sprintf("invalid Gt encoding: expected %d bytes, got %d", size, len(b)))
	}

	g := FP256BN.FP12_fromBytes(b)

	re := make([]byte, size)
	g.ToBytes(re)
	if !bytes.Equal(re, b) {
		panic("invalid Gt encoding: non-canonical field element")
	}

	if !g.Isunity() && !FP256BN.GTmember(g) {
		panic("invalid Gt encoding: element is not in the order-r subgroup")
	}

	return g
}

func (p *Fp256Miraclbn) NewG1FromBytes(b []byte) driver.G1 {
	return &fp256bnMiraclG1{*decodeFp256bnMiraclG1(b, false)}
}

func (p *Fp256Miraclbn) NewG2FromBytes(b []byte) driver.G2 {
	return &fp256bnMiraclG2{decodeFp256bnMiraclG2(b, false)}
}

func (p *Fp256Miraclbn) NewG1FromCompressed(b []byte) driver.G1 {
	return &fp256bnMiraclG1{*decodeFp256bnMiraclG1(b, true)}
}

func (p *Fp256Miraclbn) NewG2FromCompressed(b []byte) driver.G2 {
	return &fp256bnMiraclG2{decodeFp256bnMiraclG2(b, true)}
}

func (p *Fp256Miraclbn) NewGtFromBytes(b []byte) driver.Gt {
	return &fp256bnMiraclGt{*decodeFp256bnMiraclGt(b)}
}

func (p *Fp256Miraclbn) HashToG1(data []byte) driver.G1 {
	return &fp256bnMiraclG1{*bls_hash_to_point_miracl(data, []byte{})}
}

func (p *Fp256Miraclbn) HashToG1WithDomain(data, domain []byte) driver.G1 {
	return &fp256bnMiraclG1{*bls_hash_to_point_miracl(data, domain)}
}

// HashToG2 always panics: FP256BN has no supported hash-to-G2 map. Use a curve
// with native G2 hashing support (e.g. BLS12-381, BN254) if G2 hashing is required.
func (p *Fp256Miraclbn) HashToG2(data []byte) driver.G2 {
	panic("driver/amcl: HashToG2 is not implemented for FP256BN — use a curve with native G2 hashing support (e.g. BLS12-381, BN254)")
}

// HashToG2WithDomain always panics: FP256BN has no supported hash-to-G2 map. Use a curve
// with native G2 hashing support (e.g. BLS12-381, BN254) if G2 hashing is required.
func (p *Fp256Miraclbn) HashToG2WithDomain(data, domain []byte) driver.G2 {
	panic("driver/amcl: HashToG2WithDomain is not implemented for FP256BN — use a curve with native G2 hashing support (e.g. BLS12-381, BN254)")
}

/*********************************************************************/

type fp256bnMiraclG1 struct {
	FP256BN.ECP
}

func (e *fp256bnMiraclG1) Clone(a driver.G1) {
	e.ECP.Copy(&a.(*fp256bnMiraclG1).ECP)
}

func (e *fp256bnMiraclG1) Copy() driver.G1 {
	c := FP256BN.NewECP()
	c.Copy(&e.ECP)

	return &fp256bnMiraclG1{*c}
}

func (e *fp256bnMiraclG1) Add(a driver.G1) {
	e.ECP.Add(&a.(*fp256bnMiraclG1).ECP)
}

func (e *fp256bnMiraclG1) Mul(a driver.Zr) driver.G1 {
	return &fp256bnMiraclG1{*FP256BN.G1mul(&e.ECP, bigToMiraclBIG(&a.(*common.BaseZr).Int))}
}

func (e *fp256bnMiraclG1) Mul2(ee driver.Zr, Q driver.G1, f driver.Zr) driver.G1 {
	return &fp256bnMiraclG1{*e.ECP.Mul2(bigToMiraclBIG(&ee.(*common.BaseZr).Int), &Q.(*fp256bnMiraclG1).ECP, bigToMiraclBIG(&f.(*common.BaseZr).Int))}
}

func (e *fp256bnMiraclG1) Mul2InPlace(ee driver.Zr, Q driver.G1, f driver.Zr) {
	e.ECP = *e.ECP.Mul2(bigToMiraclBIG(&ee.(*common.BaseZr).Int), &Q.(*fp256bnMiraclG1).ECP, bigToMiraclBIG(&f.(*common.BaseZr).Int))
}

func (e *fp256bnMiraclG1) Equals(a driver.G1) bool {
	return e.ECP.Equals(&a.(*fp256bnMiraclG1).ECP)
}

func (e *fp256bnMiraclG1) IsInfinity() bool {
	return e.Is_infinity()
}

func (e *fp256bnMiraclG1) Bytes() []byte {
	b := make([]byte, 2*int(FP256BN.MODBYTES)+1)
	miraclG1Infinity(&e.ECP).ToBytes(b, false)

	return b
}

func (e *fp256bnMiraclG1) Compressed() []byte {
	b := make([]byte, int(FP256BN.MODBYTES)+1)
	miraclG1Infinity(&e.ECP).ToBytes(b, true)

	return b
}

func (e *fp256bnMiraclG1) Sub(a driver.G1) {
	e.ECP.Sub(&a.(*fp256bnMiraclG1).ECP)
}

func (b *fp256bnMiraclG1) String() string {
	rawstr := b.ToString()
	m := g1StrRegexp.FindAllStringSubmatch(rawstr, -1)
	if m == nil {
		// e.g. the point at infinity, which AMCL renders as "infinity"
		return rawstr
	}

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
	return &fp256bnMiraclG2{e.ECP2.Mul(bigToMiraclBIG(&a.(*common.BaseZr).Int))}
}

func (e *fp256bnMiraclG2) Affine() {
	e.ECP2.Affine()
}

func (e *fp256bnMiraclG2) Bytes() []byte {
	b := make([]byte, 4*int(FP256BN.MODBYTES)+1)
	miraclG2Infinity(e.ECP2).ToBytes(b, false)

	return b
}

func (e *fp256bnMiraclG2) Compressed() []byte {
	b := make([]byte, 2*int(FP256BN.MODBYTES)+1)
	miraclG2Infinity(e.ECP2).ToBytes(b, true)

	return b
}

func (b *fp256bnMiraclG2) String() string {
	return b.ToString()
}

// NewZrFromBytesCanonical implements driver.CanonicalZrDecoder.
func (p *Fp256Miraclbn) NewZrFromBytesCanonical(b []byte) (driver.Zr, error) {
	return common.NewBaseZrFromBytesCanonical(&p.Modulus, b)
}

// miraclG1Infinity returns the canonical identity if P is the identity, else P.
// MIRACL serialises a computed identity from its leftover coordinates.
func miraclG1Infinity(P *FP256BN.ECP) *FP256BN.ECP {
	if P.Is_infinity() {
		return FP256BN.NewECP()
	}

	return P
}

// miraclG2Infinity is the G2 analogue of miraclG1Infinity.
func miraclG2Infinity(P *FP256BN.ECP2) *FP256BN.ECP2 {
	if P.Is_infinity() {
		return FP256BN.NewECP2()
	}

	return P
}
