/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package math

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/IBM/mathlib/driver"
	"github.com/IBM/mathlib/driver/amcl"
	"github.com/IBM/mathlib/driver/gurvy"
	"github.com/IBM/mathlib/driver/kilic"
	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"
)

type CurveID int

const (
	FP256BN_AMCL CurveID = iota
	BN254
	FP256BN_AMCL_MIRACL
	BLS12_381
	BLS12_377_GURVY
	BLS12_381_GURVY
	BLS12_381_BBS
	BLS12_381_BBS_GURVY
)

func CurveIDToString(id CurveID) string {
	switch id {
	case FP256BN_AMCL:
		return "FP256BN_AMCL"
	case BN254:
		return "BN254"
	case FP256BN_AMCL_MIRACL:
		return "FP256BN_AMCL_MIRACL"
	case BLS12_381:
		return "BLS12_381"
	case BLS12_377_GURVY:
		return "BLS12_377_GURVY"
	case BLS12_381_GURVY:
		return "BLS12_381_GURVY"
	case BLS12_381_BBS:
		return "BLS12_381_BBS"
	case BLS12_381_BBS_GURVY:
		return "BLS12_381_BBS_GURVY"
	default:
		panic(fmt.Sprintf("unknown curve %d", id))
	}
}

var Curves []*Curve = []*Curve{
	{
		c:                    amcl.NewFp256bn(),
		GenG1:                &G1{g1: (&amcl.Fp256bn{}).GenG1(), curveID: FP256BN_AMCL},
		GenG2:                &G2{g2: (&amcl.Fp256bn{}).GenG2(), curveID: FP256BN_AMCL},
		GenGt:                &Gt{gt: (&amcl.Fp256bn{}).GenGt(), curveID: FP256BN_AMCL},
		GroupOrder:           &Zr{zr: amcl.NewFp256bn().GroupOrder(), curveID: FP256BN_AMCL},
		CoordByteSize:        (&amcl.Fp256bn{}).CoordinateByteSize(),
		G1ByteSize:           (&amcl.Fp256bn{}).G1ByteSize(),
		CompressedG1ByteSize: (&amcl.Fp256bn{}).CompressedG1ByteSize(),
		G2ByteSize:           (&amcl.Fp256bn{}).G2ByteSize(),
		CompressedG2ByteSize: (&amcl.Fp256bn{}).CompressedG2ByteSize(),
		ScalarByteSize:       (&amcl.Fp256bn{}).ScalarByteSize(),
		FrCompressedSize:     32,
		curveID:              FP256BN_AMCL,
	},
	{
		c:                    gurvy.NewBn254(),
		GenG1:                &G1{g1: (&gurvy.Bn254{}).GenG1(), curveID: BN254},
		GenG2:                &G2{g2: (&gurvy.Bn254{}).GenG2(), curveID: BN254},
		GenGt:                &Gt{gt: (&gurvy.Bn254{}).GenGt(), curveID: BN254},
		GroupOrder:           &Zr{zr: gurvy.NewBn254().GroupOrder(), curveID: BN254},
		CoordByteSize:        (&gurvy.Bn254{}).CoordinateByteSize(),
		G1ByteSize:           (&gurvy.Bn254{}).G1ByteSize(),
		CompressedG1ByteSize: (&gurvy.Bn254{}).CompressedG1ByteSize(),
		G2ByteSize:           (&gurvy.Bn254{}).G2ByteSize(),
		CompressedG2ByteSize: (&gurvy.Bn254{}).CompressedG2ByteSize(),
		ScalarByteSize:       (&gurvy.Bn254{}).ScalarByteSize(),
		FrCompressedSize:     32,
		curveID:              BN254,
	},
	{
		c:                    amcl.NewFp256Miraclbn(),
		GenG1:                &G1{g1: (&amcl.Fp256Miraclbn{}).GenG1(), curveID: FP256BN_AMCL_MIRACL},
		GenG2:                &G2{g2: (&amcl.Fp256Miraclbn{}).GenG2(), curveID: FP256BN_AMCL_MIRACL},
		GenGt:                &Gt{gt: (&amcl.Fp256Miraclbn{}).GenGt(), curveID: FP256BN_AMCL_MIRACL},
		GroupOrder:           &Zr{zr: amcl.NewFp256Miraclbn().GroupOrder(), curveID: FP256BN_AMCL_MIRACL},
		CoordByteSize:        (&amcl.Fp256Miraclbn{}).CoordinateByteSize(),
		G1ByteSize:           (&amcl.Fp256Miraclbn{}).G1ByteSize(),
		CompressedG1ByteSize: (&amcl.Fp256Miraclbn{}).CompressedG1ByteSize(),
		G2ByteSize:           (&amcl.Fp256Miraclbn{}).G2ByteSize(),
		CompressedG2ByteSize: (&amcl.Fp256Miraclbn{}).CompressedG2ByteSize(),
		ScalarByteSize:       (&amcl.Fp256Miraclbn{}).ScalarByteSize(),
		FrCompressedSize:     32,
		curveID:              FP256BN_AMCL_MIRACL,
	},
	{
		c:                    kilic.NewBls12_381(),
		GenG1:                &G1{g1: (&kilic.Bls12_381{}).GenG1(), curveID: BLS12_381},
		GenG2:                &G2{g2: (&kilic.Bls12_381{}).GenG2(), curveID: BLS12_381},
		GenGt:                &Gt{gt: (&kilic.Bls12_381{}).GenGt(), curveID: BLS12_381},
		GroupOrder:           &Zr{zr: kilic.NewBls12_381().GroupOrder(), curveID: BLS12_381},
		CoordByteSize:        (&kilic.Bls12_381{}).CoordinateByteSize(),
		G1ByteSize:           (&kilic.Bls12_381{}).G1ByteSize(),
		CompressedG1ByteSize: (&kilic.Bls12_381{}).CompressedG1ByteSize(),
		G2ByteSize:           (&kilic.Bls12_381{}).G2ByteSize(),
		CompressedG2ByteSize: (&kilic.Bls12_381{}).CompressedG2ByteSize(),
		ScalarByteSize:       (&kilic.Bls12_381{}).ScalarByteSize(),
		FrCompressedSize:     32,
		curveID:              BLS12_381,
	},
	{
		c:                    gurvy.NewBls12_377(),
		GenG1:                &G1{g1: (&gurvy.Bls12_377{}).GenG1(), curveID: BLS12_377_GURVY},
		GenG2:                &G2{g2: (&gurvy.Bls12_377{}).GenG2(), curveID: BLS12_377_GURVY},
		GenGt:                &Gt{gt: (&gurvy.Bls12_377{}).GenGt(), curveID: BLS12_377_GURVY},
		GroupOrder:           &Zr{zr: gurvy.NewBls12_377().GroupOrder(), curveID: BLS12_377_GURVY},
		CoordByteSize:        (&gurvy.Bls12_377{}).CoordinateByteSize(),
		G1ByteSize:           (&gurvy.Bls12_377{}).G1ByteSize(),
		CompressedG1ByteSize: (&gurvy.Bls12_377{}).CompressedG1ByteSize(),
		G2ByteSize:           (&gurvy.Bls12_377{}).G2ByteSize(),
		CompressedG2ByteSize: (&gurvy.Bls12_377{}).CompressedG2ByteSize(),
		ScalarByteSize:       (&gurvy.Bls12_377{}).ScalarByteSize(),
		FrCompressedSize:     32,
		curveID:              BLS12_377_GURVY,
	},
	{
		c:                    gurvy.NewBls12_381(),
		GenG1:                &G1{g1: (&gurvy.Bls12_381{}).GenG1(), curveID: BLS12_381_GURVY},
		GenG2:                &G2{g2: (&gurvy.Bls12_381{}).GenG2(), curveID: BLS12_381_GURVY},
		GenGt:                &Gt{gt: (&gurvy.Bls12_381{}).GenGt(), curveID: BLS12_381_GURVY},
		GroupOrder:           &Zr{zr: gurvy.NewBls12_381().GroupOrder(), curveID: BLS12_381_GURVY},
		CoordByteSize:        (&gurvy.Bls12_381{}).CoordinateByteSize(),
		G1ByteSize:           (&gurvy.Bls12_381{}).G1ByteSize(),
		CompressedG1ByteSize: (&gurvy.Bls12_381{}).CompressedG1ByteSize(),
		G2ByteSize:           (&gurvy.Bls12_381{}).G2ByteSize(),
		CompressedG2ByteSize: (&gurvy.Bls12_381{}).CompressedG2ByteSize(),
		ScalarByteSize:       (&gurvy.Bls12_381{}).ScalarByteSize(),
		FrCompressedSize:     32,
		curveID:              BLS12_381_GURVY,
	},
	{
		c:                    kilic.NewBls12_381BBS(),
		GenG1:                &G1{g1: kilic.NewBls12_381BBS().GenG1(), curveID: BLS12_381_BBS},
		GenG2:                &G2{g2: kilic.NewBls12_381BBS().GenG2(), curveID: BLS12_381_BBS},
		GenGt:                &Gt{gt: kilic.NewBls12_381BBS().GenGt(), curveID: BLS12_381_BBS},
		GroupOrder:           &Zr{zr: kilic.NewBls12_381().GroupOrder(), curveID: BLS12_381_BBS},
		CoordByteSize:        kilic.NewBls12_381BBS().CoordinateByteSize(),
		G1ByteSize:           kilic.NewBls12_381BBS().G1ByteSize(),
		CompressedG1ByteSize: kilic.NewBls12_381BBS().CompressedG1ByteSize(),
		G2ByteSize:           kilic.NewBls12_381BBS().G2ByteSize(),
		CompressedG2ByteSize: kilic.NewBls12_381BBS().CompressedG2ByteSize(),
		ScalarByteSize:       kilic.NewBls12_381BBS().ScalarByteSize(),
		FrCompressedSize:     32,
		curveID:              BLS12_381_BBS,
	},
	{
		c:                    gurvy.NewBls12_381BBS(),
		GenG1:                &G1{g1: gurvy.NewBls12_381BBS().GenG1(), curveID: BLS12_381_BBS_GURVY},
		GenG2:                &G2{g2: gurvy.NewBls12_381BBS().GenG2(), curveID: BLS12_381_BBS_GURVY},
		GenGt:                &Gt{gt: gurvy.NewBls12_381BBS().GenGt(), curveID: BLS12_381_BBS_GURVY},
		GroupOrder:           &Zr{zr: gurvy.NewBls12_381().GroupOrder(), curveID: BLS12_381_BBS_GURVY},
		CoordByteSize:        gurvy.NewBls12_381BBS().CoordinateByteSize(),
		G1ByteSize:           gurvy.NewBls12_381BBS().G1ByteSize(),
		CompressedG1ByteSize: gurvy.NewBls12_381BBS().CompressedG1ByteSize(),
		G2ByteSize:           gurvy.NewBls12_381BBS().G2ByteSize(),
		CompressedG2ByteSize: gurvy.NewBls12_381BBS().CompressedG2ByteSize(),
		ScalarByteSize:       gurvy.NewBls12_381BBS().ScalarByteSize(),
		FrCompressedSize:     32,
		curveID:              BLS12_381_BBS_GURVY,
	},
}

/*********************************************************************/

type Zr struct {
	zr      driver.Zr
	curveID CurveID
}

func (z *Zr) CurveID() CurveID {
	return z.curveID
}

func (z *Zr) Plus(a *Zr) *Zr {
	return &Zr{zr: z.zr.Plus(a.zr), curveID: z.curveID}
}

func (z *Zr) Minus(a *Zr) *Zr {
	return &Zr{zr: z.zr.Minus(a.zr), curveID: z.curveID}
}

func (z *Zr) Mul(a *Zr) *Zr {
	return &Zr{zr: z.zr.Mul(a.zr), curveID: z.curveID}
}

func (z *Zr) Mod(a *Zr) {
	z.zr.Mod(a.zr)
}

func (z *Zr) PowMod(a *Zr) *Zr {
	return &Zr{zr: z.zr.PowMod(a.zr), curveID: z.curveID}
}

func (z *Zr) InvModP(a *Zr) {
	z.zr.InvModP(a.zr)
}

func (z *Zr) Bytes() []byte {
	return z.zr.Bytes()
}

func (z *Zr) Equals(a *Zr) bool {
	return z.zr.Equals(a.zr)
}

func (z *Zr) Copy() *Zr {
	return &Zr{zr: z.zr.Copy(), curveID: z.curveID}
}

func (z *Zr) Clone(a *Zr) {
	z.zr.Clone(a.zr)
}

func (z *Zr) String() string {
	return z.zr.String()
}

func (z *Zr) Neg() {
	z.zr.Neg()
}

var zerobytes = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
var onebytes = []byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}

func (z *Zr) Uint() (uint64, error) {
	b := z.Bytes()
	if !bytes.Equal(zerobytes, b[:32-8]) && !bytes.Equal(onebytes, b[:32-8]) {
		return 0, fmt.Errorf("out of range")
	}

	return uint64(binary.BigEndian.Uint64(b[32-8:])), nil
}

func (z *Zr) Int() (int64, error) {
	b := z.Bytes()
	if !bytes.Equal(zerobytes, b[:32-8]) && !bytes.Equal(onebytes, b[:32-8]) {
		return 0, fmt.Errorf("out of range")
	}

	return int64(binary.BigEndian.Uint64(b[32-8:])), nil
}

func (z *Zr) IsZero() bool {
	b := z.Bytes()
	for _, byt := range b {
		if byt != 0 {
			return false
		}
	}
	return true
}

/*********************************************************************/

type G1 struct {
	g1      driver.G1
	curveID CurveID
}

func (g *G1) CurveID() CurveID {
	return g.curveID
}

func (g *G1) Clone(a *G1) {
	g.g1.Clone(a.g1)
}

func (g *G1) Copy() *G1 {
	return &G1{g1: g.g1.Copy(), curveID: g.curveID}
}

func (g *G1) Add(a *G1) {
	g.g1.Add(a.g1)
}

func (g *G1) Mul(a *Zr) *G1 {
	return &G1{g1: g.g1.Mul(a.zr), curveID: g.curveID}
}

func (g *G1) Mul2(e *Zr, Q *G1, f *Zr) *G1 {
	return &G1{g1: g.g1.Mul2(e.zr, Q.g1, f.zr), curveID: g.curveID}
}

func (g *G1) Equals(a *G1) bool {
	return g.g1.Equals(a.g1)
}

func (g *G1) Bytes() []byte {
	return g.g1.Bytes()
}

func (g *G1) Compressed() []byte {
	return g.g1.Compressed()
}

func (g *G1) Sub(a *G1) {
	g.g1.Sub(a.g1)
}

func (g *G1) IsInfinity() bool {
	return g.g1.IsInfinity()
}

func (g *G1) String() string {
	return g.g1.String()
}

func (g *G1) Neg() {
	g.g1.Neg()
}

/*********************************************************************/

type G2 struct {
	g2      driver.G2
	curveID CurveID
}

func (g *G2) CurveID() CurveID {
	return g.curveID
}

func (g *G2) Clone(a *G2) {
	g.g2.Clone(a.g2)
}

func (g *G2) Copy() *G2 {
	return &G2{g2: g.g2.Copy(), curveID: g.curveID}
}

func (g *G2) Mul(a *Zr) *G2 {
	return &G2{g2: g.g2.Mul(a.zr), curveID: g.curveID}
}

func (g *G2) Add(a *G2) {
	g.g2.Add(a.g2)
}

func (g *G2) Sub(a *G2) {
	g.g2.Sub(a.g2)
}

func (g *G2) Affine() {
	g.g2.Affine()
}

func (g *G2) Bytes() []byte {
	return g.g2.Bytes()
}

func (g *G2) Compressed() []byte {
	return g.g2.Compressed()
}

func (g *G2) String() string {
	return g.g2.String()
}

func (g *G2) Equals(a *G2) bool {
	return g.g2.Equals(a.g2)
}

/*********************************************************************/

type Gt struct {
	gt      driver.Gt
	curveID CurveID
}

func (g *Gt) CurveID() CurveID {
	return g.curveID
}

func (g *Gt) Equals(a *Gt) bool { // ASK ALE: I think this doesn't behave properly.
	return g.gt.Equals(a.gt)
}

func (g *Gt) Inverse() {
	g.gt.Inverse()
}

func (g *Gt) Mul(a *Gt) {
	g.gt.Mul(a.gt)
}

func (g *Gt) Exp(z *Zr) *Gt {
	return &Gt{gt: g.gt.Exp(z.zr), curveID: g.curveID}
}

func (g *Gt) IsUnity() bool {
	return g.gt.IsUnity()
}

func (g *Gt) String() string {
	return g.gt.ToString()
}

func (g *Gt) Bytes() []byte {
	return g.gt.Bytes()
}

/*********************************************************************/

type Curve struct {
	c                    driver.Curve
	GenG1                *G1
	GenG2                *G2
	GenGt                *Gt
	GroupOrder           *Zr
	CoordByteSize        int
	G1ByteSize           int
	CompressedG1ByteSize int
	G2ByteSize           int
	CompressedG2ByteSize int
	ScalarByteSize       int
	FrCompressedSize     int
	curveID              CurveID
}

func (c *Curve) Rand() (io.Reader, error) {
	return c.c.Rand()
}

func (c *Curve) NewRandomZr(rng io.Reader) *Zr {
	return &Zr{zr: c.c.NewRandomZr(rng), curveID: c.curveID}
}

func (c *Curve) NewZrFromBytes(b []byte) *Zr {
	return &Zr{zr: c.c.NewZrFromBytes(b), curveID: c.curveID}
}

func (c *Curve) NewG1FromBytes(b []byte) (p *G1, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("failure [%s]", r)
			p = nil
		}
	}()

	p = &G1{g1: c.c.NewG1FromBytes(b), curveID: c.curveID}
	return
}

func (c *Curve) NewG2FromBytes(b []byte) (p *G2, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("failure [%s]", r)
			p = nil
		}
	}()

	p = &G2{g2: c.c.NewG2FromBytes(b), curveID: c.curveID}
	return
}

func (c *Curve) NewG1FromCompressed(b []byte) (p *G1, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("failure [%s]", r)
			p = nil
		}
	}()

	p = &G1{g1: c.c.NewG1FromCompressed(b), curveID: c.curveID}
	return
}

func (c *Curve) NewG2FromCompressed(b []byte) (p *G2, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("failure [%s]", r)
			p = nil
		}
	}()

	p = &G2{g2: c.c.NewG2FromCompressed(b), curveID: c.curveID}
	return
}

func (c *Curve) NewGtFromBytes(b []byte) (p *Gt, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("failure [%s]", r)
			p = nil
		}
	}()

	p = &Gt{gt: c.c.NewGtFromBytes(b), curveID: c.curveID}
	return
}

func (c *Curve) NewZrFromInt(i int64) *Zr {
	return &Zr{zr: c.c.NewZrFromInt64(i), curveID: c.curveID}
}

func (c *Curve) NewZrFromUint64(i uint64) *Zr {
	return &Zr{zr: c.c.NewZrFromUint64(i), curveID: c.curveID}
}

func (c *Curve) NewG2() *G2 {
	return &G2{g2: c.c.NewG2(), curveID: c.curveID}
}

func (c *Curve) NewG1() *G1 {
	return &G1{g1: c.c.NewG1(), curveID: c.curveID}
}

func (c *Curve) Pairing(a *G2, b *G1) *Gt {
	return &Gt{gt: c.c.Pairing(a.g2, b.g1), curveID: c.curveID}
}

func (c *Curve) Pairing2(p *G2, q *G1, r *G2, s *G1) *Gt {
	return &Gt{gt: c.c.Pairing2(p.g2, r.g2, q.g1, s.g1), curveID: c.curveID}
}

func (c *Curve) FExp(a *Gt) *Gt {
	return &Gt{gt: c.c.FExp(a.gt), curveID: c.curveID}
}

func (c *Curve) HashToZr(data []byte) *Zr {
	return &Zr{zr: c.c.HashToZr(data), curveID: c.curveID}
}

func (c *Curve) HashToG1(data []byte) *G1 {
	return &G1{g1: c.c.HashToG1(data), curveID: c.curveID}
}

func (c *Curve) HashToG1WithDomain(data, domain []byte) *G1 {
	return &G1{g1: c.c.HashToG1WithDomain(data, domain), curveID: c.curveID}
}

func (c *Curve) HashToG2(data []byte) *G2 {
	return &G2{g2: c.c.HashToG2(data), curveID: c.curveID}
}

func (c *Curve) HashToG2WithDomain(data, domain []byte) *G2 {
	return &G2{g2: c.c.HashToG2WithDomain(data, domain), curveID: c.curveID}
}

func (c *Curve) ModSub(a, b, m *Zr) *Zr {
	return &Zr{zr: c.c.ModSub(a.zr, b.zr, m.zr), curveID: c.curveID}
}

func (c *Curve) ModAdd(a, b, m *Zr) *Zr {
	return &Zr{zr: c.c.ModAdd(a.zr, b.zr, m.zr), curveID: c.curveID}
}

func (c *Curve) ModMul(a1, b1, m *Zr) *Zr {
	return &Zr{zr: c.c.ModMul(a1.zr, b1.zr, m.zr), curveID: c.curveID}
}

func (c *Curve) ModNeg(a1, m *Zr) *Zr {
	return &Zr{zr: c.c.ModNeg(a1.zr, m.zr), curveID: c.curveID}
}

func (c *Curve) ZeroG1() *G1 {
	zero := c.GenG1.Copy()
	zero.Sub(c.GenG1)
	return zero
}

func (c *Curve) NewPolynomial() *Polynomial {
	return &Polynomial{
		curveID: c.curveID,
		coeffs:  make([]*Zr, 0),
	}
}

func (c *Curve) NewPolynomialDeg(d int) *Polynomial {
	// should return poly with d+1 length array of coefficients
	return &Polynomial{
		curveID: c.curveID,
		coeffs:  make([]*Zr, d+1),
	}
}

func (c *Curve) NewPolynomialFromCoeffs(coeffs []*Zr) *Polynomial {
	return &Polynomial{
		curveID: c.curveID,
		coeffs:  coeffs,
	}
}

func (c *Curve) CompareTwoPairings(p1 *G1, q1 *G2,
	p2 *G1, q2 *G2) bool {

	// DEVIATION FROM aries-bbs-go, so that this function can be used black-box
	p2Copy := p2.Copy()
	p2Copy.Neg()

	p := c.Pairing2(q1, p1, q2, p2Copy)
	p = c.FExp(p)

	return p.IsUnity()
}

func (c *Curve) ID() CurveID {
	return c.curveID
}

/*********************************************************************/

type Polynomial struct {
	curveID CurveID
	coeffs  []*Zr
}

func (p *Polynomial) CurveID() CurveID {
	return p.curveID
}

// Return coefficients as an array of field elements
func (p *Polynomial) Coeffs() []*Zr {
	return p.coeffs
}

func (p *Polynomial) AppendCoeff(coeff *Zr) {
	p.coeffs = append(p.coeffs, coeff)
}

func (p *Polynomial) Degree() int {
	return len(p.coeffs) - 1
}

func (p *Polynomial) Eval(x *Zr) *Zr {
	deg := p.Degree()
	res := p.coeffs[deg].Copy()
	for i := deg - 1; i >= 0; i-- {
		res = res.Mul(x)
		res = res.Plus(p.coeffs[i])
	}

	return res
}

/*********************************************************************/

type CommitmentBuilder struct {
	bases   []*G1
	scalars []*Zr
}

func NewCommitmentBuilder(expectedSize int) *CommitmentBuilder {
	return &CommitmentBuilder{
		bases:   make([]*G1, 0, expectedSize),
		scalars: make([]*Zr, 0, expectedSize),
	}
}

func (cb *CommitmentBuilder) Add(base *G1, scalar *Zr) {
	cb.bases = append(cb.bases, base)
	cb.scalars = append(cb.scalars, scalar)
}

func (cb *CommitmentBuilder) Build() *G1 {
	return SumOfG1Products(cb.bases, cb.scalars)
}

/*********************************************************************/

type ChallengeProvider interface {
	GetChallenge() *Zr
}

type GenericChallProvider struct {
	curve      *Curve
	commitment *G1
	bases      []*G1
	nonce      []byte
}

func (c *Curve) NewChallengeProvider(commitment *G1, bases []*G1, nonce []byte) ChallengeProvider {
	return &GenericChallProvider{
		curve:      c,
		commitment: commitment,
		bases:      bases,
		nonce:      nonce,
	}
}

func (p *GenericChallProvider) GetChallenge() *Zr {
	challengeBytes := make([]byte, 0)
	// add bytes for every base
	for _, base := range p.bases {
		challengeBytes = append(challengeBytes, base.Bytes()...)
	}
	// add bytes for commitment
	challengeBytes = append(challengeBytes, p.commitment.Bytes()...)
	// add bytes for nonce
	challengeBytes = append(challengeBytes, p.curve.NonceToFrBytes(p.nonce)...)
	// convert final challenge bytes to a field element
	challenge := p.curve.FrFromOKM(challengeBytes)
	return challenge
}

/*********************************************************************/

func SumOfG1Products(bases []*G1, scalars []*Zr) *G1 {
	var res *G1

	for i := 0; i < len(bases); i++ {
		b := bases[i]
		s := scalars[i]

		g := b.Mul(s.Copy())
		if res == nil {
			res = g
		} else {
			res.Add(g)
		}
	}

	return res
}

func (c *Curve) NonceToFrBytes(nonce []byte) []byte {
	fieldElem := c.FrFromOKM(nonce)
	return fieldElem.Bytes()
}

func (c *Curve) FrFromOKM(message []byte) *Zr {
	const (
		eightBytes = 8
		okmMiddle  = 24
	)

	// We pass a null key so error is impossible here.
	h, _ := blake2b.New384(nil) //nolint:errcheck

	// blake2b.digest() does not return an error.
	_, _ = h.Write(message)
	okm := h.Sum(nil)
	emptyEightBytes := make([]byte, eightBytes)

	elm := c.NewZrFromBytes(append(emptyEightBytes, okm[:okmMiddle]...))

	f2192 := c.NewZrFromBytes([]byte{
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	})

	elm = elm.Mul(f2192)

	fr := c.NewZrFromBytes(append(emptyEightBytes, okm[okmMiddle:]...))
	elm = elm.Plus(fr)

	return elm
}

/*********************************************************************/

type ProofG1 struct {
	Commitment *G1
	Responses  []*Zr
}

func NewProofG1(commitment *G1, responses []*Zr) *ProofG1 {
	return &ProofG1{
		Commitment: commitment,
		Responses:  responses,
	}
}

func (c *Curve) StartProofG1(rng io.Reader, bases []*G1, secrets []*Zr) *ProverCommittedG1 {
	proverCommiting := NewProverCommittingG1()
	for _, base := range bases {
		proverCommiting.Commit(c, rng, base)
	}

	return proverCommiting.Finish()
}

func (c *Curve) FinishProofG1(prover *ProverCommittedG1, secrets []*Zr, challProvider ChallengeProvider) *ProofG1 {

	challenge := challProvider.GetChallenge()

	proof := prover.GenerateProof(challenge, secrets)

	return proof
}

func (c *Curve) VerifyProofG1(pg1 *ProofG1, R *G1, bases []*G1, challProvider ChallengeProvider) bool {

	challenge := challProvider.GetChallenge()

	points := append(bases, R)
	scalars := append(pg1.Responses, challenge)

	contribution := SumOfG1Products(points, scalars)
	contribution.Sub(pg1.Commitment)

	return contribution.IsInfinity()
}

// ToBytes converts ProofG1 to bytes.
// Note that this doesn't encode bases, verifier should know them.
func (pg1 *ProofG1) ToBytes() []byte {
	bytes := make([]byte, 0)

	commitmentBytes := pg1.Commitment.Compressed()
	bytes = append(bytes, commitmentBytes...)

	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(pg1.Responses)))
	bytes = append(bytes, lenBytes...)

	for i := range pg1.Responses {
		responseBytes := pg1.Responses[i].Copy().Bytes()
		bytes = append(bytes, responseBytes...)
	}

	return bytes
}

// ParseProofG1 parses ProofG1 from bytes.
func (c *Curve) ParseProofG1(bytes []byte) (*ProofG1, error) {
	if len(bytes) < c.CompressedG1ByteSize+4 {
		return nil, errors.New("invalid size of G1 signature proof")
	}

	offset := 0

	commitment, err := c.NewG1FromCompressed(bytes[:c.CompressedG1ByteSize])
	if err != nil {
		return nil, fmt.Errorf("parse G1 point: %w", err)
	}

	offset += c.CompressedG1ByteSize
	length := int(binary.BigEndian.Uint32(bytes[offset : offset+4]))
	offset += 4

	if len(bytes) < c.CompressedG1ByteSize+4+length*c.FrCompressedSize {
		return nil, errors.New("invalid size of G1 signature proof")
	}

	responses := make([]*Zr, length)
	for i := 0; i < length; i++ {
		responses[i] = c.NewZrFromBytes(bytes[offset : offset+c.FrCompressedSize])
		offset += c.FrCompressedSize
	}

	return NewProofG1(commitment, responses), nil
}

////////////////////////////////////////////////////////////////////////////////
//// OLD STUFF FROM ARIES-BBS-GO, NEEDS TO BE REFACTORED
////////////////////////////////////////////////////////////////////////////////

// ProverCommittedG1 helps to generate a ProofG1.
type ProverCommittedG1 struct {
	Bases           []*G1
	BlindingFactors []*Zr
	Commitment      *G1
}

// ToBytes converts ProverCommittedG1 to bytes.
func (g *ProverCommittedG1) ToBytes() []byte {
	bytes := make([]byte, 0)

	for _, base := range g.Bases {
		bytes = append(bytes, base.Bytes()...)
	}

	return append(bytes, g.Commitment.Bytes()...)
}

// GenerateProof generates proof ProofG1 for all secrets.
func (g *ProverCommittedG1) GenerateProof(challenge *Zr, secrets []*Zr) *ProofG1 {
	responses := make([]*Zr, len(g.Bases))

	for i := range g.BlindingFactors {
		c := challenge.Mul(secrets[i])

		s := g.BlindingFactors[i].Minus(c)
		responses[i] = s
	}

	return &ProofG1{
		Commitment: g.Commitment,
		Responses:  responses,
	}
} ////////////////////////////////////////////////////////////////////////

// ProverCommittingG1 is a proof of knowledge of messages in a vector commitment.
type ProverCommittingG1 struct {
	bases           []*G1
	BlindingFactors []*Zr
}

// NewProverCommittingG1 creates a new ProverCommittingG1.
func NewProverCommittingG1() *ProverCommittingG1 {
	return &ProverCommittingG1{
		bases:           make([]*G1, 0),
		BlindingFactors: make([]*Zr, 0),
	}
}

// Commit append a base point and randomly generated blinding factor.
func (pc *ProverCommittingG1) Commit(c *Curve, rng io.Reader, base *G1) {
	pc.bases = append(pc.bases, base)
	r := c.NewRandomZr(rng)
	pc.BlindingFactors = append(pc.BlindingFactors, r)
}

// Finish helps to generate ProverCommittedG1 after commitment of all base points.
func (pc *ProverCommittingG1) Finish() *ProverCommittedG1 {
	commitment := SumOfG1Products(pc.bases, pc.BlindingFactors)

	return &ProverCommittedG1{
		Bases:           pc.bases,
		BlindingFactors: pc.BlindingFactors,
		Commitment:      commitment,
	}
}
