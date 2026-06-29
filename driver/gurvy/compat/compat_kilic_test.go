/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package compat provides oracle-based compatibility tests that verify
// the driver/gurvy implementations match kilic/bls12-381 exactly.
//
// This package lives in its own Go module so that the kilic dependency is
// isolated here and does not appear in the main module's dependency graph.
// Run with:
//
//	cd driver/gurvy/compat && go test ./...
package compat_test

import (
	"crypto/sha256"
	"testing"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/hash_to_curve"
	kilic "github.com/kilic/bls12-381"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/IBM/mathlib/driver/gurvy"
)

// ---------------------------------------------------------------------------
// Kilic internal-function bindings via go:linkname
// ---------------------------------------------------------------------------

type kilicFe [6]uint64

//go:linkname kilicAdd github.com/kilic/bls12-381.add
func kilicAdd(c, a, b *kilicFe)

//go:linkname kilicToMont github.com/kilic/bls12-381.toMont
func kilicToMont(a, b *kilicFe)

//go:linkname kilicFromMont github.com/kilic/bls12-381.fromMont
func kilicFromMont(c, a *kilicFe)

//go:linkname kilicInverse github.com/kilic/bls12-381.inverse
func kilicInverse(inv, e *kilicFe)

//go:linkname kilicIsQuadraticNonResidue github.com/kilic/bls12-381.isQuadraticNonResidue
func kilicIsQuadraticNonResidue(a *kilicFe) bool

//go:linkname kilicSqrt github.com/kilic/bls12-381.sqrt
func kilicSqrt(c, a *kilicFe) bool

//go:linkname kilicSquare github.com/kilic/bls12-381.square
func kilicSquare(c, a *kilicFe)

//go:linkname kilicNeg github.com/kilic/bls12-381.neg
func kilicNeg(c, a *kilicFe)

//go:linkname kilicIsogenyMapG1 github.com/kilic/bls12-381.isogenyMapG1
func kilicIsogenyMapG1(x, y *kilicFe)

//go:linkname kilicSwuMapG1 github.com/kilic/bls12-381.swuMapG1
func kilicSwuMapG1(u *kilicFe) (*kilicFe, *kilicFe)

//go:linkname kilicHashToFpXMDSHA256 github.com/kilic/bls12-381.hashToFpXMDSHA256
func kilicHashToFpXMDSHA256(msg []byte, domain []byte, count int) ([]*kilicFe, error)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func toKilicFe(p *fp.Element) *kilicFe {
	return (*kilicFe)(unsafe.Pointer(p))
}

func toFpElement(p *kilicFe) *fp.Element {
	return (*fp.Element)(unsafe.Pointer(p))
}

// ---------------------------------------------------------------------------
// Oracle tests
// ---------------------------------------------------------------------------

func TestCompatIsQuadraticResidue(t *testing.T) {
	for range 1000 {
		var x fp.Element
		_, err := x.SetRandom()
		require.NoError(t, err)

		kX := toKilicFe(&x)
		kilicNonResidue := kilicIsQuadraticNonResidue(kX)
		gurvyResidue := gurvy.IsQuadraticResidue(&x)

		if kilicNonResidue {
			assert.Equal(t, uint64(0), gurvyResidue, "expected non-residue")
		} else {
			assert.Equal(t, uint64(1), gurvyResidue, "expected residue")
		}
	}
}

func TestCompatSqrt(t *testing.T) {
	for range 1000 {
		var x fp.Element
		_, err := x.SetRandom()
		require.NoError(t, err)

		var x2 fp.Element
		x2.Square(&x)

		kX2 := toKilicFe(&x2)
		var kSqrt kilicFe
		ok := kilicSqrt(&kSqrt, kX2)
		require.True(t, ok, "kilic sqrt failed")

		var gSqrt fp.Element
		gurvy.Sqrt(&gSqrt, &x2)

		gSqrtNeg := gSqrt
		gSqrtNeg.Neg(&gSqrtNeg)

		kSqrtFp := toFpElement(&kSqrt)
		assert.True(t, gSqrt.Equal(kSqrtFp) || gSqrtNeg.Equal(kSqrtFp), "sqrt mismatch")
	}
}

func TestCompatSgn0(t *testing.T) {
	// signBE is defined in kilic as checking if negZ.cmp(z) > -1
	// where negZ = -z, z = fromMont(e).
	// So signBE(e) is true if -z >= z, which means z > (p-1)/2 or z == 0.
	for range 1000 {
		var x fp.Element
		_, err := x.SetRandom()
		require.NoError(t, err)

		kX := toKilicFe(&x)

		var z kilicFe
		kilicFromMont(&z, kX)
		var negZ kilicFe
		kilicNeg(&negZ, &z)

		expectedSignBE := true
		for j := 5; j >= 0; j-- {
			if negZ[j] < z[j] {
				expectedSignBE = false

				break
			} else if negZ[j] > z[j] {
				break
			}
		}

		gurvySign := gurvy.Sgn0(&x)
		if expectedSignBE {
			assert.Equal(t, uint64(1), gurvySign, "expected signBE match")
		} else {
			assert.Equal(t, uint64(0), gurvySign, "expected signBE match")
		}
	}
}

func TestCompatSwuMapG1BE(t *testing.T) {
	for range 1000 {
		var u fp.Element
		_, err := u.SetRandom()
		require.NoError(t, err)

		kU := toKilicFe(&u)
		kX, kY := kilicSwuMapG1(kU)

		gX, gY := gurvy.SwuMapG1BE(&u)

		assert.Equal(t, toFpElement(kX).Bytes(), gX.Bytes(), "X coordinate mismatch")
		assert.Equal(t, toFpElement(kY).Bytes(), gY.Bytes(), "Y coordinate mismatch")
	}
}

func TestCompatIsogenyMapG1(t *testing.T) {
	// The two isogeny implementations (kilic vs gnark) use different polynomial
	// representations and only agree on valid points of the isogenous curve E'.
	// Generate valid E' points via kilicSwuMapG1 before comparing.
	for i := range 1000 {
		var u fp.Element
		_, err := u.SetRandom()
		require.NoError(t, err)

		kU := toKilicFe(&u)
		kX, kY := kilicSwuMapG1(kU)

		kilicIsogenyMapG1(kX, kY)

		gX, gY := gurvy.SwuMapG1BE(&u)
		importX := *gX
		importY := *gY
		hash_to_curve.G1Isogeny(&importX, &importY)

		assert.Equal(t, toFpElement(kX).Bytes(), importX.Bytes(), "Isogeny X mismatch at i=%d", i)
		assert.Equal(t, toFpElement(kY).Bytes(), importY.Bytes(), "Isogeny Y mismatch at i=%d", i)
	}
}

func TestCompatHash(t *testing.T) {
	for i := range 100 {
		msg := []byte(string(rune(i)) + "test_hash_msg")
		domain := []byte("test_hash_domain")

		kU, err := kilicHashToFpXMDSHA256(msg, domain, 2)
		require.NoError(t, err)

		gU, err := gurvy.Hash(msg, domain, 2, sha256.New)
		require.NoError(t, err)

		assert.Equal(t, toFpElement(kU[0]).Bytes(), gU[0].Bytes(), "u0 mismatch for input %d", i)
		assert.Equal(t, toFpElement(kU[1]).Bytes(), gU[1].Bytes(), "u1 mismatch for input %d", i)
	}
}

func TestCompatHashToG1GenericBESwu(t *testing.T) {
	g1Kilic := kilic.NewG1()

	for i := range 100 {
		msg := []byte(string(rune(i)) + "test_message_compat")
		domain := []byte("test_domain_compat")

		kPoint, err := g1Kilic.HashToCurve(msg, domain)
		require.NoError(t, err)

		kRaw := g1Kilic.ToUncompressed(kPoint)

		gPoint, err := gurvy.HashToG1GenericBESwu(msg, domain, sha256.New)
		require.NoError(t, err)

		gRaw := gPoint.RawBytes()

		assert.Equal(t, kRaw[:], gRaw[:], "HashToG1GenericBESwu mismatch for input %d", i)
	}
}
