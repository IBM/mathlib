/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package unsupported

import (
	"io"

	"github.com/IBM/mathlib/driver"
)

func NewUnsupportedCurve() driver.Curve {
	return &UnsupportedCurve{}
}

type UnsupportedCurve struct{}

func (*UnsupportedCurve) Pairing(driver.G2, driver.G1) driver.Gt {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) Pairing2(p2a, p2b driver.G2, p1a, p1b driver.G1) driver.Gt {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) FExp(driver.Gt) driver.Gt {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) ModMul(a1, b1, m driver.Zr) driver.Zr {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) ModNeg(a1, m driver.Zr) driver.Zr {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) GenG1() driver.G1 {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) GenG2() driver.G2 {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) GenGt() driver.Gt {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) GroupOrder() driver.Zr {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) CoordinateByteSize() int {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) G1ByteSize() int {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) CompressedG1ByteSize() int {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) G2ByteSize() int {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) CompressedG2ByteSize() int {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) ScalarByteSize() int {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) NewG1() driver.G1 {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) NewG2() driver.G2 {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) NewZrFromBytes(b []byte) driver.Zr {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) NewZrFromInt(i int64) driver.Zr {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) NewG1FromBytes(b []byte) driver.G1 {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) NewG1FromCompressed(b []byte) driver.G1 {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) NewG2FromBytes(b []byte) driver.G2 {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) NewG2FromCompressed(b []byte) driver.G2 {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) NewGtFromBytes(b []byte) driver.Gt {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) ModAdd(a, b, m driver.Zr) driver.Zr {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) ModSub(a, b, m driver.Zr) driver.Zr {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) HashToZr(data []byte) driver.Zr {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) HashToG1(data []byte) driver.G1 {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) HashToG1WithDomain(data, domain []byte) driver.G1 {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) NewRandomZr(rng io.Reader) driver.Zr {
	panic("this driver is no longer supported")
}

func (*UnsupportedCurve) Rand() (io.Reader, error) {
	panic("this driver is no longer supported")
}

type UnsupportedZr struct{}

func (*UnsupportedZr) Plus(driver.Zr) driver.Zr {
	panic("this driver is no longer supported")
}

func (*UnsupportedZr) Minus(driver.Zr) driver.Zr {
	panic("this driver is no longer supported")
}

func (*UnsupportedZr) Mul(driver.Zr) driver.Zr {
	panic("this driver is no longer supported")
}

func (*UnsupportedZr) Mod(driver.Zr) {
	panic("this driver is no longer supported")
}

func (*UnsupportedZr) PowMod(driver.Zr) driver.Zr {
	panic("this driver is no longer supported")
}

func (*UnsupportedZr) InvModP(driver.Zr) {
	panic("this driver is no longer supported")
}

func (*UnsupportedZr) Bytes() []byte {
	panic("this driver is no longer supported")
}

func (*UnsupportedZr) Equals(driver.Zr) bool {
	panic("this driver is no longer supported")
}

func (*UnsupportedZr) Copy() driver.Zr {
	panic("this driver is no longer supported")
}

func (*UnsupportedZr) Clone(a driver.Zr) {
	panic("this driver is no longer supported")
}

func (*UnsupportedZr) String() string {
	panic("this driver is no longer supported")
}

func (*UnsupportedZr) Neg() {
	panic("this driver is no longer supported")
}

type UnsupportedG1 struct{}

func (*UnsupportedG1) Clone(driver.G1) {
	panic("this driver is no longer supported")
}

func (*UnsupportedG1) Copy() driver.G1 {
	panic("this driver is no longer supported")
}

func (*UnsupportedG1) Add(driver.G1) {
	panic("this driver is no longer supported")
}

func (*UnsupportedG1) Mul(driver.Zr) driver.G1 {
	panic("this driver is no longer supported")
}

func (*UnsupportedG1) Mul2(e driver.Zr, Q driver.G1, f driver.Zr) driver.G1 {
	panic("this driver is no longer supported")
}

func (*UnsupportedG1) Equals(driver.G1) bool {
	panic("this driver is no longer supported")
}

func (*UnsupportedG1) Bytes() []byte {
	panic("this driver is no longer supported")
}

func (*UnsupportedG1) Compressed() []byte {
	panic("this driver is no longer supported")
}

func (*UnsupportedG1) Sub(driver.G1) {
	panic("this driver is no longer supported")
}

func (*UnsupportedG1) IsInfinity() bool {
	panic("this driver is no longer supported")
}

func (*UnsupportedG1) String() string {
	panic("this driver is no longer supported")
}

func (*UnsupportedG1) Neg() {
	panic("this driver is no longer supported")
}

type UnsupportedG2 struct{}

func (*UnsupportedG2) Clone(driver.G2) {
	panic("this driver is no longer supported")
}

func (*UnsupportedG2) Copy() driver.G2 {
	panic("this driver is no longer supported")
}

func (*UnsupportedG2) Mul(driver.Zr) driver.G2 {
	panic("this driver is no longer supported")
}

func (*UnsupportedG2) Add(driver.G2) {
	panic("this driver is no longer supported")
}

func (*UnsupportedG2) Sub(driver.G2) {
	panic("this driver is no longer supported")
}

func (*UnsupportedG2) Affine() {
	panic("this driver is no longer supported")
}

func (*UnsupportedG2) Bytes() []byte {
	panic("this driver is no longer supported")
}

func (*UnsupportedG2) Compressed() []byte {
	panic("this driver is no longer supported")
}

func (*UnsupportedG2) String() string {
	panic("this driver is no longer supported")
}

func (*UnsupportedG2) Equals(driver.G2) bool {
	panic("this driver is no longer supported")
}

type UnsupportedGt struct{}

func (*UnsupportedGt) Equals(driver.Gt) bool {
	panic("this driver is no longer supported")
}

func (*UnsupportedGt) Inverse() {
	panic("this driver is no longer supported")
}

func (*UnsupportedGt) Mul(driver.Gt) {
	panic("this driver is no longer supported")
}

func (*UnsupportedGt) IsUnity() bool {
	panic("this driver is no longer supported")
}

func (*UnsupportedGt) ToString() string {
	panic("this driver is no longer supported")
}

func (*UnsupportedGt) Bytes() []byte {
	panic("this driver is no longer supported")
}

func (*UnsupportedGt) Exp(driver.Zr) driver.Gt {
	panic("this driver is no longer supported")
}
