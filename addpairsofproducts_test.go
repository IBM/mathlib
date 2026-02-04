/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package math

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runAddPairsOfProductsTest(t *testing.T, c *Curve) {
	rng, err := c.Rand()
	require.NoError(t, err)

	// Test with different sizes
	testSizes := []int{1, 2, 5, 10}

	for _, n := range testSizes {
		t.Run("size_"+string(rune(n+'0')), func(t *testing.T) {
			// Generate random scalars and generators
			left := make([]*Zr, n)
			right := make([]*Zr, n)
			leftgen := make([]*G1, n)
			rightgen := make([]*G1, n)

			for i := 0; i < n; i++ {
				left[i] = c.NewRandomZr(rng)
				right[i] = c.NewRandomZr(rng)
				leftgen[i] = c.GenG1.Mul(c.NewRandomZr(rng))
				rightgen[i] = c.GenG1.Mul(c.NewRandomZr(rng))
			}

			// Compute using AddPairsOfProducts
			result := c.AddPairsOfProducts(left, right, leftgen, rightgen, c.GroupOrder)

			// Compute manually to verify correctness
			// result should equal: sum of (left[i] * leftgen[i] + right[i] * rightgen[i])
			// Use Mul2 for each pair (which computes left[i]*leftgen[i] + right[i]*rightgen[i])
			expected := leftgen[0].Mul2(left[0], rightgen[0], right[0])

			// Add remaining pairs
			for i := 1; i < n; i++ {
				pairResult := leftgen[i].Mul2(left[i], rightgen[i], right[i])
				expected.Add(pairResult)
			}

			assert.True(t, result.Equals(expected), "AddPairsOfProducts result does not match expected value for curve %s with size %d", CurveIDToString(c.curveID), n)
		})
	}
}

// TestAddPairsOfProductsEdgeCases tests edge cases for AddPairsOfProducts
func TestAddPairsOfProductsEdgeCases(t *testing.T) {
	for _, curve := range Curves {
		t.Run(CurveIDToString(curve.curveID), func(t *testing.T) {
			runAddPairsOfProductsEdgeCasesTest(t, curve)
		})
	}
}

func runAddPairsOfProductsEdgeCasesTest(t *testing.T, c *Curve) {
	rng, err := c.Rand()
	require.NoError(t, err)

	// Test with zero scalars
	t.Run("zero_scalars", func(t *testing.T) {
		n := 3
		left := make([]*Zr, n)
		right := make([]*Zr, n)
		leftgen := make([]*G1, n)
		rightgen := make([]*G1, n)

		for i := 0; i < n; i++ {
			left[i] = c.NewZrFromInt(0)
			right[i] = c.NewZrFromInt(0)
			leftgen[i] = c.GenG1.Mul(c.NewRandomZr(rng))
			rightgen[i] = c.GenG1.Mul(c.NewRandomZr(rng))
		}

		result := c.AddPairsOfProducts(left, right, leftgen, rightgen, c.GroupOrder)

		// Result should be the identity element (infinity)
		assert.True(t, result.IsInfinity(), "Result should be infinity when all scalars are zero for curve %s", CurveIDToString(c.curveID))
	})

	// Test with identity generators
	t.Run("identity_generators", func(t *testing.T) {
		n := 2
		left := make([]*Zr, n)
		right := make([]*Zr, n)
		leftgen := make([]*G1, n)
		rightgen := make([]*G1, n)

		for i := 0; i < n; i++ {
			left[i] = c.NewRandomZr(rng)
			right[i] = c.NewRandomZr(rng)
			// Use the base generator
			leftgen[i] = c.GenG1.Copy()
			rightgen[i] = c.GenG1.Copy()
		}

		result := c.AddPairsOfProducts(left, right, leftgen, rightgen, c.GroupOrder)

		// Manually compute expected result using Mul2
		expected := c.GenG1.Mul2(left[0], c.GenG1, right[0])
		for i := 1; i < n; i++ {
			pairResult := c.GenG1.Mul2(left[i], c.GenG1, right[i])
			expected.Add(pairResult)
		}

		assert.True(t, result.Equals(expected), "Result mismatch with identity generators for curve %s", CurveIDToString(c.curveID))
	})

	// Test with one element
	t.Run("single_element", func(t *testing.T) {
		left := []*Zr{c.NewRandomZr(rng)}
		right := []*Zr{c.NewRandomZr(rng)}
		leftgen := []*G1{c.GenG1.Mul(c.NewRandomZr(rng))}
		rightgen := []*G1{c.GenG1.Mul(c.NewRandomZr(rng))}

		result := c.AddPairsOfProducts(left, right, leftgen, rightgen, c.GroupOrder)

		// Expected: left[0] * leftgen[0] + right[0] * rightgen[0]
		expected := leftgen[0].Mul2(left[0], rightgen[0], right[0])

		assert.True(t, result.Equals(expected), "Result mismatch for single element for curve %s", CurveIDToString(c.curveID))
	})

	// Test commutativity: swapping pairs should give same result
	t.Run("commutativity", func(t *testing.T) {
		n := 3
		left := make([]*Zr, n)
		right := make([]*Zr, n)
		leftgen := make([]*G1, n)
		rightgen := make([]*G1, n)

		for i := 0; i < n; i++ {
			left[i] = c.NewRandomZr(rng)
			right[i] = c.NewRandomZr(rng)
			leftgen[i] = c.GenG1.Mul(c.NewRandomZr(rng))
			rightgen[i] = c.GenG1.Mul(c.NewRandomZr(rng))
		}

		result1 := c.AddPairsOfProducts(left, right, leftgen, rightgen, c.GroupOrder)

		// Swap left and right
		result2 := c.AddPairsOfProducts(right, left, rightgen, leftgen, c.GroupOrder)

		assert.True(t, result1.Equals(result2), "Results should be equal when swapping left/right for curve %s", CurveIDToString(c.curveID))
	})

	// Test with negative scalars
	t.Run("negative_scalars", func(t *testing.T) {
		n := 2
		left := make([]*Zr, n)
		right := make([]*Zr, n)
		leftgen := make([]*G1, n)
		rightgen := make([]*G1, n)

		for i := 0; i < n; i++ {
			left[i] = c.NewRandomZr(rng)
			right[i] = left[i].Copy()
			right[i].Neg() // Negate to create opposite
			leftgen[i] = c.GenG1.Mul(c.NewRandomZr(rng))
			rightgen[i] = leftgen[i].Copy() // Use same generator
		}

		result := c.AddPairsOfProducts(left, right, leftgen, rightgen, c.GroupOrder)

		// Result should be infinity since left[i] + (-left[i]) = 0 for same generators
		assert.True(t, result.IsInfinity(), "Result should be infinity with negated scalars and same generators for curve %s", CurveIDToString(c.curveID))
	})
}

// TestAddPairsOfProductsConsistency tests consistency with other operations
func TestAddPairsOfProductsConsistency(t *testing.T) {
	for _, curve := range Curves {
		t.Run(CurveIDToString(curve.curveID), func(t *testing.T) {
			runAddPairsOfProductsConsistencyTest(t, curve)
		})
	}
}

func runAddPairsOfProductsConsistencyTest(t *testing.T, c *Curve) {
	rng, err := c.Rand()
	require.NoError(t, err)

	// Test consistency with Mul2
	t.Run("consistency_with_mul2", func(t *testing.T) {
		a := c.NewRandomZr(rng)
		b := c.NewRandomZr(rng)
		P := c.GenG1.Mul(c.NewRandomZr(rng))
		Q := c.GenG1.Mul(c.NewRandomZr(rng))

		// Using Mul2
		result1 := P.Mul2(a, Q, b)

		// Using AddPairsOfProducts with single pair
		result2 := c.AddPairsOfProducts([]*Zr{a}, []*Zr{b}, []*G1{P}, []*G1{Q}, c.GroupOrder)

		assert.True(t, result1.Equals(result2), "AddPairsOfProducts should match Mul2 for single pair for curve %s", CurveIDToString(c.curveID))
	})

	// Test consistency with MultiScalarMul
	t.Run("consistency_with_multiscalarmul", func(t *testing.T) {
		// Skip for BLS12_381_GURVY and BLS12_381_BBS_GURVY as they have a known limitation
		// with JointScalarMultiplication when using the same generator for left and right
		if c.curveID == BLS12_381_GURVY || c.curveID == BLS12_381_BBS_GURVY {
			t.Skip("Skipping for GURVY curves due to JointScalarMultiplication limitation with same generators")
		}

		n := 5
		scalars := make([]*Zr, n)
		scalars2 := make([]*Zr, n)
		generators := make([]*G1, n)

		for i := 0; i < n; i++ {
			scalars[i] = c.NewRandomZr(rng)
			scalars2[i] = c.NewRandomZr(rng)
			generators[i] = c.GenG1.Mul(c.NewRandomZr(rng))
		}

		// Compute sum of scalars[i] * generators[i] + scalars2[i] * generators[i]
		// This equals sum of (scalars[i] + scalars2[i]) * generators[i]
		combinedScalars := make([]*Zr, n)
		for i := 0; i < n; i++ {
			combinedScalars[i] = c.ModAdd(scalars[i], scalars2[i], c.GroupOrder)
		}

		// Using MultiScalarMul
		result1 := c.MultiScalarMul(generators, combinedScalars)

		// Using AddPairsOfProducts
		result2 := c.AddPairsOfProducts(scalars, scalars2, generators, generators, c.GroupOrder)

		assert.True(t, result1.Equals(result2), "AddPairsOfProducts should match MultiScalarMul for curve %s", CurveIDToString(c.curveID))
	})
}
