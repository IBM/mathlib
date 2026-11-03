/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package amcl

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"github.com/IBM/mathlib/driver"
	"github.com/IBM/mathlib/driver/common"
	"github.com/hyperledger/fabric-amcl/amcl/FP256BN"
)

/*********************************************************************/

type fp256bnGt struct {
	FP256BN.FP12
}

func (a *fp256bnGt) Exp(x driver.Zr) driver.Gt {
	// FP12.Pow in this AMCL version returns the base unchanged for a zero
	// exponent, so a zero exponent is handled here explicitly. A non-zero
	// multiple of the group order is raised to the group order instead of
	// being reduced to 0, so that Exp(GroupOrder) still distinguishes elements
	// outside the order-q subgroup.
	xi := &x.(*common.BaseZr).Int
	if xi.Sign() == 0 {
		return &fp256bnGt{*FP256BN.NewFP12int(1)}
	}
	var e big.Int
	if e.Mod(xi, &modulusBig).Sign() == 0 {
		e.Set(&modulusBig)
	} else {
		e.Set(xi)
	}

	return &fp256bnGt{*a.Pow(bigToMiraclBIGCore(&e))}
}

func (a *fp256bnGt) Equals(b driver.Gt) bool {
	return a.FP12.Equals(&b.(*fp256bnGt).FP12)
}

func (a *fp256bnGt) IsUnity() bool {
	return a.Isunity()
}

func (a *fp256bnGt) Inverse() {
	a.FP12.Inverse()
}

func (a *fp256bnGt) Mul(b driver.Gt) {
	a.FP12.Mul(&b.(*fp256bnGt).FP12)
}

func (b *fp256bnGt) ToString() string {
	return b.FP12.ToString()
}

func (b *fp256bnGt) Bytes() []byte {
	bytes := make([]byte, 12*int(FP256BN.MODBYTES))
	b.ToBytes(bytes)

	return bytes
}

/*********************************************************************/

func NewFp256bn() *Fp256bn {
	return &Fp256bn{common.CurveBase{Modulus: modulusBig}}
}

type Fp256bn struct {
	common.CurveBase
}

func (p *Fp256bn) MultiScalarMul(a []driver.G1, b []driver.Zr) driver.G1 {
	g1 := p.NewG1()
	for i := range a {
		g1.Add(a[i].Mul(b[i]))
	}

	return g1
}

func (*Fp256bn) Pairing(a driver.G2, b driver.G1) driver.Gt {
	return &fp256bnGt{*FP256BN.Ate(&a.(*fp256bnG2).ECP2, &b.(*fp256bnG1).ECP)}
}

func (*Fp256bn) Pairing2(p2a, p2b driver.G2, p1a, p1b driver.G1) driver.Gt {
	return &fp256bnGt{*FP256BN.Ate2(&p2a.(*fp256bnG2).ECP2, &p1a.(*fp256bnG1).ECP, &p2b.(*fp256bnG2).ECP2, &p1b.(*fp256bnG1).ECP)}
}

func (*Fp256bn) FExp(e driver.Gt) driver.Gt {
	return &fp256bnGt{*FP256BN.Fexp(&e.(*fp256bnGt).FP12)}
}

func (*Fp256bn) GenG1() driver.G1 {
	return &fp256bnG1{*FP256BN.NewECPbigs(FP256BN.NewBIGints(FP256BN.CURVE_Gx), FP256BN.NewBIGints(FP256BN.CURVE_Gy))}
}

func (*Fp256bn) GenG2() driver.G2 {
	return &fp256bnG2{*FP256BN.NewECP2fp2s(
		FP256BN.NewFP2bigs(FP256BN.NewBIGints(FP256BN.CURVE_Pxa), FP256BN.NewBIGints(FP256BN.CURVE_Pxb)),
		FP256BN.NewFP2bigs(FP256BN.NewBIGints(FP256BN.CURVE_Pya), FP256BN.NewBIGints(FP256BN.CURVE_Pyb)))}
}

func (p *Fp256bn) GenGt() driver.Gt {
	return &fp256bnGt{*FP256BN.Fexp(FP256BN.Ate(&p.GenG2().(*fp256bnG2).ECP2, &p.GenG1().(*fp256bnG1).ECP))}
}

func (p *Fp256bn) CoordinateByteSize() int {
	return int(FP256BN.MODBYTES)
}

func (p *Fp256bn) G1ByteSize() int {
	return 2*int(FP256BN.MODBYTES) + 1
}

func (p *Fp256bn) CompressedG1ByteSize() int {
	return int(FP256BN.MODBYTES) + 1
}

func (p *Fp256bn) G2ByteSize() int {
	return 4 * int(FP256BN.MODBYTES)
}

func (p *Fp256bn) CompressedG2ByteSize() int {
	return 4 * int(FP256BN.MODBYTES)
}

func (p *Fp256bn) ScalarByteSize() int {
	return common.ScalarByteSize
}

func (p *Fp256bn) NewG1() driver.G1 {
	return &fp256bnG1{*FP256BN.NewECP()}
}

func (p *Fp256bn) NewG2() driver.G2 {
	return &fp256bnG2{*FP256BN.NewECP2()}
}

func bigToMiraclBIGCore(bi *big.Int) *FP256BN.BIG {
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

// decodeFp256bnG1 decodes a G1 point from its uncompressed (0x04||X||Y) or
// compressed ((0x02|0x03)||X) SEC1-style encoding.
//
// FP256BN.ECP_fromBytes never fails: an invalid prefix, a coordinate >= p or a
// point that is not on the curve all decode to the point at infinity, and any
// trailing bytes are ignored. We therefore enforce the exact length and prefix
// and require the decoded point to re-encode to exactly the input. This rejects
// every malformed input and leaves the canonical encoding of the point at
// infinity (as produced by Bytes/Compressed) as the only input that decodes to
// infinity.
//
// FP256BN is a BN curve, so G1 has cofactor 1: every point on the curve is in
// the order-r subgroup and no further check is needed.
func decodeFp256bnG1(b []byte, compressed bool) *FP256BN.ECP {
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

// decodeFp256bnG2 decodes a G2 point from its Xa||Xb||Ya||Yb encoding (the only
// format this driver supports, used for both Bytes and Compressed).
//
// FP256BN.ECP2_fromBytes reduces coordinates modulo p, maps points that are not
// on the twist to infinity and ignores trailing bytes, so, as for G1, we enforce
// the exact length and a canonical round trip. The twist has a large cofactor,
// so we additionally check that the point lies in the order-r subgroup G2.
func decodeFp256bnG2(b []byte) *FP256BN.ECP2 {
	size := 4 * int(FP256BN.MODBYTES)
	if len(b) != size {
		panic(fmt.Sprintf("invalid G2 encoding: expected %d bytes, got %d", size, len(b)))
	}

	P := FP256BN.ECP2_fromBytes(b)

	re := make([]byte, size)
	P.ToBytes(re)
	if !bytes.Equal(re, b) {
		panic("invalid G2 encoding: not the canonical encoding of a point on the twist")
	}

	// As for Gt (see decodeFp256bnGt), the legacy package has no membership
	// test, so we use the fast endomorphism-based one of the MIRACL core
	// package, whose uncompressed G2 layout is 0x04||Xb||Xa||Yb||Ya.
	if !P.Is_infinity() && !isFp256bnG2Member(toMiraclG2Bytes(b)) {
		panic("invalid G2 encoding: point is not in the order-r subgroup")
	}

	return P
}

// decodeFp256bnGt decodes a Gt element, requiring exact length, canonical field
// elements and membership in the order-r subgroup of Fp12^*.
func decodeFp256bnGt(b []byte) *FP256BN.FP12 {
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

	// The legacy AMCL package does not export a GT membership test. The MIRACL
	// core package implements the same curve and Fp12 tower, with an encoding
	// that lists the twelve Fp coefficients in reverse order, so we reuse its
	// (fast, Frobenius-based) membership test.
	if !g.Isunity() && !isFp256bnGtMember(reverseFpLimbs(b, int(FP256BN.MODBYTES))) {
		panic("invalid Gt encoding: element is not in the order-r subgroup")
	}

	return g
}

// toMiraclG2Bytes converts a legacy Xa||Xb||Ya||Yb G2 encoding into the MIRACL
// core uncompressed encoding 0x04||Xb||Xa||Yb||Ya.
func toMiraclG2Bytes(b []byte) []byte {
	mb := int(FP256BN.MODBYTES)
	out := make([]byte, 1, 1+4*mb)
	out[0] = 0x04
	out = append(out, b[mb:2*mb]...)
	out = append(out, b[0:mb]...)
	out = append(out, b[3*mb:4*mb]...)
	out = append(out, b[2*mb:3*mb]...)

	return out
}

// reverseFpLimbs returns a copy of b with its size-byte chunks in reverse order.
func reverseFpLimbs(b []byte, size int) []byte {
	out := make([]byte, len(b))
	n := len(b) / size
	for i := range n {
		copy(out[(n-1-i)*size:(n-i)*size], b[i*size:(i+1)*size])
	}

	return out
}

func (p *Fp256bn) NewG1FromBytes(b []byte) driver.G1 {
	return &fp256bnG1{*decodeFp256bnG1(b, false)}
}

func (p *Fp256bn) NewG2FromBytes(b []byte) driver.G2 {
	return &fp256bnG2{*decodeFp256bnG2(b)}
}

func (p *Fp256bn) NewG1FromCompressed(b []byte) driver.G1 {
	return &fp256bnG1{*decodeFp256bnG1(b, true)}
}

func (p *Fp256bn) NewG2FromCompressed(b []byte) driver.G2 {
	return &fp256bnG2{*decodeFp256bnG2(b)}
}

func (p *Fp256bn) NewGtFromBytes(b []byte) driver.Gt {
	return &fp256bnGt{*decodeFp256bnGt(b)}
}

func (p *Fp256bn) HashToG1(data []byte) driver.G1 {
	return &fp256bnG1{*FP256BN.Bls_hash(string(data))}
}

func (p *Fp256bn) HashToG1WithDomain(data, domain []byte) driver.G1 {
	mac := hmac.New(sha256.New, domain)
	mac.Write(data)

	return &fp256bnG1{*FP256BN.Bls_hash(string(mac.Sum(nil)))}
}

// HashToG2 always panics: FP256BN has no supported hash-to-G2 map. Use a curve
// with native G2 hashing support (e.g. BLS12-381, BN254) if G2 hashing is required.
func (p *Fp256bn) HashToG2(data []byte) driver.G2 {
	panic("driver/amcl: HashToG2 is not implemented for FP256BN — use a curve with native G2 hashing support (e.g. BLS12-381, BN254)")
}

// HashToG2WithDomain always panics: FP256BN has no supported hash-to-G2 map. Use a curve
// with native G2 hashing support (e.g. BLS12-381, BN254) if G2 hashing is required.
func (p *Fp256bn) HashToG2WithDomain(data, domain []byte) driver.G2 {
	panic("driver/amcl: HashToG2WithDomain is not implemented for FP256BN — use a curve with native G2 hashing support (e.g. BLS12-381, BN254)")
}

/*********************************************************************/

type fp256bnG1 struct {
	FP256BN.ECP
}

func (e *fp256bnG1) Clone(a driver.G1) {
	e.ECP.Copy(&a.(*fp256bnG1).ECP)
}

func (e *fp256bnG1) Copy() driver.G1 {
	c := FP256BN.NewECP()
	c.Copy(&e.ECP)

	return &fp256bnG1{*c}
}

func (e *fp256bnG1) Add(a driver.G1) {
	e.ECP.Add(&a.(*fp256bnG1).ECP)
}

func (e *fp256bnG1) Mul(a driver.Zr) driver.G1 {
	return &fp256bnG1{*FP256BN.G1mul(&e.ECP, bigToMiraclBIGCore(&a.(*common.BaseZr).Int))}
}

func (e *fp256bnG1) Mul2(ee driver.Zr, Q driver.G1, f driver.Zr) driver.G1 {
	return &fp256bnG1{*e.ECP.Mul2(bigToMiraclBIGCore(&ee.(*common.BaseZr).Int), &Q.(*fp256bnG1).ECP, bigToMiraclBIGCore(&f.(*common.BaseZr).Int))}
}

func (e *fp256bnG1) Mul2InPlace(ee driver.Zr, Q driver.G1, f driver.Zr) {
	v := e.ECP.Mul2(bigToMiraclBIGCore(&ee.(*common.BaseZr).Int), &Q.(*fp256bnG1).ECP, bigToMiraclBIGCore(&f.(*common.BaseZr).Int))
	e.ECP = *v
}

func (e *fp256bnG1) Equals(a driver.G1) bool {
	return e.ECP.Equals(&a.(*fp256bnG1).ECP)
}

func (e *fp256bnG1) IsInfinity() bool {
	return e.Is_infinity()
}

func (e *fp256bnG1) Bytes() []byte {
	b := make([]byte, 2*int(FP256BN.MODBYTES)+1)
	e.ToBytes(b, false)

	return b
}

func (e *fp256bnG1) Compressed() []byte {
	b := make([]byte, int(FP256BN.MODBYTES)+1)
	e.ToBytes(b, true)

	return b
}

func (e *fp256bnG1) Sub(a driver.G1) {
	e.ECP.Sub(&a.(*fp256bnG1).ECP)
}

var g1StrRegexp *regexp.Regexp = regexp.MustCompile(`^\(([0-9a-f]+),([0-9a-f]+)\)$`)

func (b *fp256bnG1) String() string {
	rawstr := b.ToString()
	m := g1StrRegexp.FindAllStringSubmatch(rawstr, -1)
	if m == nil {
		// e.g. the point at infinity, which AMCL renders as "infinity"
		return rawstr
	}

	return "(" + strings.TrimLeft(m[0][1], "0") + "," + strings.TrimLeft(m[0][2], "0") + ")"
}

func (e *fp256bnG1) Neg() {
	res := e.Mul(NewFp256bn().NewZrFromInt64(-1))
	e.ECP = res.(*fp256bnG1).ECP
}

/*********************************************************************/

type fp256bnG2 struct {
	FP256BN.ECP2
}

func (e *fp256bnG2) Equals(a driver.G2) bool {
	return e.ECP2.Equals(&a.(*fp256bnG2).ECP2)
}

func (e *fp256bnG2) Clone(a driver.G2) {
	e.ECP2.Copy(&a.(*fp256bnG2).ECP2)
}

func (e *fp256bnG2) Copy() driver.G2 {
	c := FP256BN.NewECP2()
	c.Copy(&e.ECP2)

	return &fp256bnG2{*c}
}

func (e *fp256bnG2) Add(a driver.G2) {
	e.ECP2.Add(&a.(*fp256bnG2).ECP2)
}

func (e *fp256bnG2) Sub(a driver.G2) {
	e.ECP2.Sub(&a.(*fp256bnG2).ECP2)
}

func (e *fp256bnG2) Mul(a driver.Zr) driver.G2 {
	return &fp256bnG2{*e.ECP2.Mul(bigToMiraclBIGCore(&a.(*common.BaseZr).Int))}
}

func (e *fp256bnG2) Affine() {
	e.ECP2.Affine()
}

func (e *fp256bnG2) Bytes() []byte {
	b := make([]byte, 4*int(FP256BN.MODBYTES))
	e.ToBytes(b)

	return b
}

func (e *fp256bnG2) Compressed() []byte {
	b := make([]byte, 4*int(FP256BN.MODBYTES))
	e.ToBytes(b)

	return b
}

func (b *fp256bnG2) String() string {
	return b.ToString()
}

// NewZrFromBytesCanonical implements driver.CanonicalZrDecoder.
func (p *Fp256bn) NewZrFromBytesCanonical(b []byte) (driver.Zr, error) {
	return common.NewBaseZrFromBytesCanonical(&p.Modulus, b)
}
