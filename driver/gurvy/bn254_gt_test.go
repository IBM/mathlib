/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gurvy

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/stretchr/testify/require"
)

// A cyclotomic element that is not of order r passes the cyclotomic
// pre-check of isInGT and must be rejected by its second stage.
func TestBn254GtCyclotomicNotInGT(t *testing.T) {
	var a, c, inv bn254.GT
	_, err := a.SetRandom()
	require.NoError(t, err)

	// c = (conj(a)/a)^(p^2+1) lies in the cyclotomic subgroup.
	inv.Inverse(&a)
	c.Conjugate(&a).Mul(&c, &inv)
	var f bn254.GT
	f.FrobeniusSquare(&c)
	c.Mul(&c, &f)

	var x, y bn254.GT
	x.FrobeniusSquare(&c)
	y.FrobeniusSquare(&x).Mul(&y, &c)
	require.True(t, x.Equal(&y), "c must be cyclotomic")

	require.False(t, isInGT(&c))
	b := c.Bytes()
	require.Panics(t, func() { NewBn254().NewGtFromBytes(b[:]) })
}
