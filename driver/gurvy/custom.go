/*
Copyright IBM Corp. All Rights Reserved.
Copyright 2020 ConsenSys Software Inc.

SPDX-License-Identifier: Apache-2.0
*/

package gurvy

import (
	"errors"
	"hash"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/hash_to_curve"
)

const Bits = 381 // number of bits needed to represent a Element

type Element [6]uint64

type G1Affine struct {
	X, Y fp.Element
}

// ExpandMsgXmd expands msg to a slice of lenInBytes bytes.
// Matches kilic's implementation for BESwu compatibility
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-06#section-5
// https://tools.ietf.org/html/rfc8017#section-4.1 (I2OSP/O2ISP)
func ExpandMsgXmd(msg, dst []byte, lenInBytes int, hashFunc func() hash.Hash) ([]byte, error) {
	h := hashFunc()

	ell := (lenInBytes + h.Size() - 1) / h.Size() // ceil(len_in_bytes / b_in_bytes)
	if ell > 255 {
		return nil, errors.New("invalid lenInBytes")
	}
	dstLen := len(dst)
	if dstLen > 255 {
		return nil, errors.New("invalid domain size (>255 bytes)")
	}
	sizeDomain := uint8(dstLen)

	// b₀ = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST || sizeDomain)
	h.Reset()
	if _, err := h.Write(make([]byte, h.BlockSize())); err != nil {
		return nil, err
	}
	if _, err := h.Write(msg); err != nil {
		return nil, err
	}
	if _, err := h.Write([]byte{uint8(lenInBytes >> 8), uint8(lenInBytes), uint8(0)}); err != nil { // #nosec G115
		return nil, err
	}
	if _, err := h.Write(dst); err != nil {
		return nil, err
	}
	if _, err := h.Write([]byte{sizeDomain}); err != nil {
		return nil, err
	}
	b0 := h.Sum(nil)

	// b₁ = H(b₀ || I2OSP(1, 1) || DST || sizeDomain)
	h.Reset()
	if _, err := h.Write(b0); err != nil {
		return nil, err
	}
	if _, err := h.Write([]byte{uint8(1)}); err != nil {
		return nil, err
	}
	if _, err := h.Write(dst); err != nil {
		return nil, err
	}
	if _, err := h.Write([]byte{sizeDomain}); err != nil {
		return nil, err
	}
	b1 := h.Sum(nil)

	res := make([]byte, lenInBytes)
	copy(res[:h.Size()], b1)

	for i := 2; i <= ell; i++ {
		// b_i = H(strxor(b₀, b_(i - 1)) || I2OSP(i, 1) || DST || sizeDomain)
		h.Reset()
		strxor := make([]byte, h.Size())
		for j := range h.Size() {
			strxor[j] = b0[j] ^ b1[j]
		}
		if _, err := h.Write(strxor); err != nil {
			return nil, err
		}
		if _, err := h.Write([]byte{uint8(i)}); err != nil {
			return nil, err
		}
		if _, err := h.Write(dst); err != nil {
			return nil, err
		}
		if _, err := h.Write([]byte{sizeDomain}); err != nil {
			return nil, err
		}
		b1 = h.Sum(nil)
		copy(res[h.Size()*(i-1):min(h.Size()*i, len(res))], b1)
	}

	return res, nil
}

// Hash msg to count prime field elements.
// Uses the same method as kilic for BESwu compatibility:
// splits 64 bytes into two 32-byte chunks, converts each to field element,
// then combines as e1 + e0 * F where F = 2^256 * R (mod p)
func Hash(msg, dst []byte, count int, hashFunc func() hash.Hash) ([]fp.Element, error) {
	const L = 64 // bytes per field element (per kilic's hashToFpXMD)

	lenInBytes := count * L
	pseudoRandomBytes, err := ExpandMsgXmd(msg, dst, lenInBytes, hashFunc)
	if err != nil {
		return nil, err
	}

	// F = 2^256 * R (Montgomery form)
	// From kilic: F = 2^256 * R mod p
	var F fp.Element
	F[0] = 0x75b3cd7c5ce820f
	F[1] = 0x3ec6ba621c3edb0b
	F[2] = 0x168a13d82bff6bce
	F[3] = 0x87663c4bf8c449d2
	F[4] = 0x15f34c83ddc8d830
	F[5] = 0xf9628b49caa2e85

	res := make([]fp.Element, count)
	for i := range count {
		chunk := pseudoRandomBytes[i*L : (i+1)*L]
		// Split into two 32-byte chunks, right-align in 48-byte arrays (like kilic)
		a0 := make([]byte, 48)
		copy(a0[16:], chunk[:32]) // copy to bytes 16-47 (right-aligned)
		a1 := make([]byte, 48)
		copy(a1[16:], chunk[32:]) // copy to bytes 16-47 (right-aligned)

		var e0, e1 fp.Element
		e0.SetBytes(a0)
		e1.SetBytes(a1)

		// e1 + e0 * F
		var tmp fp.Element
		tmp.Mul(&e0, &F)
		res[i].Add(&e1, &tmp)
	}

	return res, nil
}

func HashToG1GenericBESwu(msg, dst []byte, hashFunc func() hash.Hash) (bls12381.G1Affine, error) {
	u, err := Hash(msg, dst, 2*1, hashFunc)
	if err != nil {
		return bls12381.G1Affine{}, err
	}

	xQ0, yQ0 := SwuMapG1BE(&u[0])
	xQ1, yQ1 := SwuMapG1BE(&u[1])

	Q0 := G1Affine{*xQ0, *yQ0}
	Q1 := G1Affine{*xQ1, *yQ1}

	// Add the two E' points first, then apply isogeny — matches kilic's HashToCurve order.
	var _Q0, _Q1 bls12381.G1Jac
	_Q0.FromAffine((*bls12381.G1Affine)(&Q0))
	_Q1.FromAffine((*bls12381.G1Affine)(&Q1)).AddAssign(&_Q0)

	var sum bls12381.G1Affine
	sum.FromJacobian(&_Q1)

	hash_to_curve.G1Isogeny(&sum.X, &sum.Y)

	var sumJac bls12381.G1Jac
	sumJac.FromAffine(&sum)
	sumJac.ClearCofactor(&sumJac)

	var res bls12381.G1Affine
	res.FromJacobian(&sumJac)

	return res, nil
}
