/*
Copyright IBM Corp. All Rights Reserved.
Copyright 2020 ConsenSys Software Inc.

SPDX-License-Identifier: Apache-2.0
*/

package gurvy

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
)

// SWU parameters for G1 (from kilic, in Montgomery form)
// These match the BLS12-381 curve parameters for Simplified SWU map
var (
	// Curve coefficients in Montgomery form
	swuA = fp.Element{
		0x2f65aa0e9af5aa51,
		0x86464c2d1e8416c3,
		0xb85ce591b7bd31e2,
		0x27e11c91b5f24e7c,
		0x28376eda6bfc1835,
		0x155455c3e5071d85,
	}
	swuB = fp.Element{
		0xfb996971fe22a1e0,
		0x9aa93eb35b742d6f,
		0x8c476013de99c5c4,
		0x873e27c3a221e571,
		0xca72b5e45a52d888,
		0x06824061418a386b,
	}

	// SWU Z parameter and its inverse
	swuZ = fp.Element{
		0x886c00000023ffdc,
		0x0f70008d3090001d,
		0x77672417ed5828c3,
		0x9dac23e943dc1740,
		0x50553f1b9c131521,
		0x078c712fbe0ab6e8,
	}
	swuZInv = fp.Element{
		0x0e8a2e8ba2e83e10,
		0x5b28ba2ca4d745d1,
		0x678cd5473847377a,
		0x4c506dd8a8076116,
		0x9bcb227d79284139,
		0x0e8d3154b0ba099a,
	}

	// -b/a in Montgomery form
	swuMinusBOverA = fp.Element{
		0x052583c93555a7fe,
		0x3b40d72430f93c82,
		0x1b75faa0105ec983,
		0x2527e7dc63851767,
		0x99fffd1f34fc181d,
		0x097cab54770ca0d3,
	}
)

// Sqrt computes the square root of a field element using Tonelli-Shanks
// Since q ≡ 3 (mod 4), sqrt(x) = x^((q+1)/4)
func Sqrt(z *fp.Element, x *fp.Element) {
	z.Sqrt(x)
}

// IsQuadraticResidue checks if x is a quadratic residue using Euler's criterion
// Returns 1 if quadratic residue, 0 otherwise
func IsQuadraticResidue(x *fp.Element) uint64 {
	if x.IsZero() {
		return 1
	}
	var tmp fp.Element
	tmp.Sqrt(x)
	if tmp.IsZero() {
		return 0
	}

	return 1
}

// Sgn0 returns the sign of a field element.
// Matches kilic's big-endian sign (returns 1 if x <= (p-1)/2, 0 otherwise)
func Sgn0(x *fp.Element) uint64 {
	bits := x.Bits()
	var pMinus1Over2 = [6]uint64{
		0xdcff7fffffffd555,
		0xf55ffff58a9ffff,
		0xb39869507b587b12,
		0xb23ba5c279c2895f,
		0x258dd3db21a5d66b,
		0xd0088f51cbff34d,
	}
	for i := 5; i >= 0; i-- {
		if bits[i] < pMinus1Over2[i] {
			return 1
		} else if bits[i] > pMinus1Over2[i] {
			return 0
		}
	}

	return 1
}

// signLE returns the parity sign of a field element.
// Matches kilic's sign() function: returns true if the least-significant bit
// of the canonical (non-Montgomery) representation is 0.
func signLE(x *fp.Element) bool {
	bits := x.Bits()

	return bits[0]&1 == 0
}

// SwuMapG1BE implements the Simplified SWU map for G1.
// The name "BE" refers to kilic's naming; the sign normalisation uses the
// same parity (LE) convention as kilic's swuMapG1 (sign() = r[0]&1==0).
// Returns x, y coordinates of the mapped point on the isogenous curve E'.
func SwuMapG1BE(u *fp.Element) (*fp.Element, *fp.Element) {
	var tv0, tv1, x1, x2, gx1, gx2, x, y2, y fp.Element

	// tv0 = u^2
	tv0.Square(u)

	// tv0 = tv0 * z
	tv0.Mul(&tv0, &swuZ)

	// tv1 = tv0^2
	tv1.Square(&tv0)

	// x1 = tv0 + tv1
	x1.Add(&tv0, &tv1)

	// x1 = x1^(-1)
	x1.Inverse(&x1)

	// e1 = x1 == 0
	e1 := x1.IsZero()

	// x1 = x1 + 1
	var one fp.Element
	one.SetOne()
	x1.Add(&x1, &one)

	// if e1: x1 = zInv
	if e1 {
		x1.Set(&swuZInv)
	}

	// x1 = x1 * (-b/a)
	x1.Mul(&x1, &swuMinusBOverA)

	// gx1 = x1^3 + a*x1 + b
	// gx1 = x1^2
	gx1.Square(&x1)
	// gx1 = gx1 + a
	gx1.Add(&gx1, &swuA)
	// gx1 = gx1 * x1
	gx1.Mul(&gx1, &x1)
	// gx1 = gx1 + b
	gx1.Add(&gx1, &swuB)

	// x2 = tv0 * x1
	x2.Mul(&tv0, &x1)

	// tv1 = tv0 * tv1
	tv1.Mul(&tv0, &tv1)

	// gx2 = gx1 * tv1
	gx2.Mul(&gx1, &tv1)

	// e2 = gx1 is quadratic residue
	e2 := IsQuadraticResidue(&gx1)

	// if e2: x = x1, y2 = gx1 else: x = x2, y2 = gx2
	if e2 == 1 {
		x.Set(&x1)
		y2.Set(&gx1)
	} else {
		x.Set(&x2)
		y2.Set(&gx2)
	}

	// y = sqrt(y2)
	Sqrt(&y, &y2)

	// if sign(y) != sign(u): y = -y
	// Uses parity (LE) sign to match kilic's swuMapG1
	if signLE(&y) != signLE(u) {
		y.Neg(&y)
	}

	return &x, &y
}
