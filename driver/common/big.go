/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"math/big"

	"github.com/IBM/mathlib/driver"
)

var onebytes = []byte{
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
}
var onebig = new(big.Int).SetBytes(onebytes)

const ScalarByteSize = 32

func BigToBytes(bi *big.Int) []byte {
	b := bi.Bytes()

	if bi.Sign() >= 0 {
		return append(make([]byte, ScalarByteSize-len(b)), b...)
	}

	twoscomp := new(big.Int).Set(onebig)
	pos := new(big.Int).Neg(bi)
	twoscomp = twoscomp.Sub(twoscomp, pos)
	twoscomp = twoscomp.Add(twoscomp, big.NewInt(1))
	b = twoscomp.Bytes()

	return append(onebytes[:ScalarByteSize-len(b)], b...)
}

type BaseZr struct {
	big.Int
	Modulus big.Int

	// isGroupOrder marks the Zr returned by CurveBase.GroupOrder. Like the
	// rawBigInt-backed GroupOrder of the bls12381 driver, it keeps its raw
	// value q in IsZero, IsOne, Bytes and Equals (so GroupOrder.Bytes() still
	// returns the encoding of q, not of 0). Every in-place operation clears it.
	isGroupOrder bool
}

// reduced returns the value of b reduced into the canonical range [0, Modulus).
// When b is already in that range (the common case) it returns &b.Int without
// allocating; otherwise the reduced value is written into tmp and tmp is returned.
// BaseZr values are not kept reduced by every operation (e.g. Plus, Minus, Neg,
// NewZrFromBytes), so every comparison must go through reduced to compare
// residues rather than raw integers.
//
// Note: like the rest of BaseZr (math/big), this is not constant time.
func (b *BaseZr) reduced(tmp *big.Int) *big.Int {
	if b.isGroupOrder || b.Modulus.Sign() == 0 || (b.Sign() >= 0 && b.Cmp(&b.Modulus) < 0) {
		return &b.Int
	}

	// big.Int.Mod implements Euclidean modulus: the result is always in [0, |m|).
	return tmp.Mod(&b.Int, &b.Modulus)
}

func (b *BaseZr) IsZero() bool {
	var tmp big.Int

	return b.reduced(&tmp).Sign() == 0
}

func (b *BaseZr) IsOne() bool {
	var tmp big.Int
	bits := b.reduced(&tmp).Bits()

	return len(bits) == 1 && bits[0] == 1
}

func (b *BaseZr) BigInt() *big.Int {
	return &b.Int
}

func (b *BaseZr) Plus(a driver.Zr) driver.Zr {
	rv := &BaseZr{Modulus: b.Modulus}
	rv.Add(&b.Int, &a.(*BaseZr).Int)

	return rv
}

func (b *BaseZr) Minus(a driver.Zr) driver.Zr {
	rv := &BaseZr{Modulus: b.Modulus}
	rv.Sub(&b.Int, &a.(*BaseZr).Int)

	return rv
}

func (b *BaseZr) Mul(a driver.Zr) driver.Zr {
	rv := &BaseZr{Modulus: b.Modulus}
	rv.Int.Mul(&b.Int, &a.(*BaseZr).Int)
	rv.Int.Mod(&rv.Int, &b.Modulus)

	return rv
}

func (b *BaseZr) PowMod(x driver.Zr) driver.Zr {
	rv := &BaseZr{Modulus: b.Modulus}
	rv.Exp(&b.Int, &x.(*BaseZr).Int, &b.Modulus)

	return rv
}

func (b *BaseZr) Mod(a driver.Zr) {
	b.Int.Mod(&b.Int, &a.(*BaseZr).Int)
	b.isGroupOrder = false
}

func (b *BaseZr) InvModP(p driver.Zr) {
	b.ModInverse(&b.Int, &p.(*BaseZr).Int)
	b.isGroupOrder = false
}

func (b *BaseZr) InvModOrder() {
	b.ModInverse(&b.Int, &b.Modulus)
	b.isGroupOrder = false
}

func (b *BaseZr) Bytes() []byte {
	var target big.Int

	return BigToBytes(b.reduced(&target))
}

// Equals reports whether b and p represent the same residue modulo the group order.
func (b *BaseZr) Equals(p driver.Zr) bool {
	var t1, t2 big.Int

	return b.reduced(&t1).Cmp(p.(*BaseZr).reduced(&t2)) == 0
}

func (b *BaseZr) Copy() driver.Zr {
	rv := &BaseZr{Modulus: b.Modulus, isGroupOrder: b.isGroupOrder}
	rv.Set(&b.Int)

	return rv
}

func (b *BaseZr) Clone(a driver.Zr) {
	src := a.(*BaseZr)
	// big.Int.Set preserves the sign (Bytes/SetBytes would drop it).
	b.Set(&src.Int)
	b.isGroupOrder = src.isGroupOrder
}

func (b *BaseZr) String() string {
	return b.Text(16)
}

func (b *BaseZr) Neg() {
	b.Int.Neg(&b.Int)
	b.isGroupOrder = false
}
