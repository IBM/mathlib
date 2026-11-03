/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package amcl

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/IBM/mathlib/driver/common"
	amcl "github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	amclcore "github.com/hyperledger/fabric-amcl/core/FP256BN"
	"github.com/stretchr/testify/require"
)

// Twist point with x = 1 + 0*i: on the FP256BN sextic twist, not in the order-q subgroup.
const (
	twistX  = "0000000000000000000000000000000000000000000000000000000000000001"
	twistX0 = "0000000000000000000000000000000000000000000000000000000000000000"
	twistYa = "c8931067e59cbf08d406b44ddde32960f67bcad8fe69bc5e469e9ba74ccc1225"
	twistYb = "a646cec84f20954d589dba3331ab71ba4321d1663c8aea6da59fb69d261559ca"
)

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)

	return b
}

func groupOrderZr() *common.BaseZr {
	var q big.Int
	q.Set(&modulusBig)

	return &common.BaseZr{Int: q, Modulus: modulusBig}
}

// P.Mul(GroupOrder) is the usual subgroup-membership test: it must not be
// turned into a multiplication by 0 by reducing the group order.
func TestMulByGroupOrderDetectsNonSubgroupPoint(t *testing.T) {
	t.Run("FP256BN_AMCL", func(t *testing.T) {
		x := amcl.NewFP2bigs(amcl.FromBytes(hexBytes(t, twistX)), amcl.FromBytes(hexBytes(t, twistX0)))
		y := amcl.NewFP2bigs(amcl.FromBytes(hexBytes(t, twistYa)), amcl.FromBytes(hexBytes(t, twistYb)))
		raw := amcl.NewECP2fp2s(x, y)
		require.False(t, raw.Is_infinity(), "sanity: the point is on the twist")
		p := &fp256bnG2{*raw}

		id := &fp256bnG2{*amcl.NewECP2()}
		require.False(t, p.Mul(groupOrderZr()).Equals(id), "P.Mul(q) must not be the identity for P outside G2")
		require.True(t, (&fp256bnG2{*amcl.ECP2_generator()}).Mul(groupOrderZr()).Equals(id), "G.Mul(q) must be the identity")
	})

	t.Run("FP256BN_AMCL_MIRACL", func(t *testing.T) {
		x := amclcore.NewFP2bigs(amclcore.FromBytes(hexBytes(t, twistX)), amclcore.FromBytes(hexBytes(t, twistX0)))
		y := amclcore.NewFP2bigs(amclcore.FromBytes(hexBytes(t, twistYa)), amclcore.FromBytes(hexBytes(t, twistYb)))
		raw := amclcore.NewECP2fp2s(x, y)
		if raw.Is_infinity() {
			t.Skip("twist point not representable with the core package's field layout")
		}
		p := &fp256bnMiraclG2{raw}

		id := &fp256bnMiraclG2{amclcore.NewECP2()}
		require.False(t, p.Mul(groupOrderZr()).Equals(id), "P.Mul(q) must not be the identity for P outside G2")
		require.True(t, (&fp256bnMiraclG2{amclcore.ECP2_generator()}).Mul(groupOrderZr()).Equals(id), "G.Mul(q) must be the identity")
	})
}

// Gt.Exp(GroupOrder) is the Gt counterpart of the subgroup test above: it must
// still detect an Fp12 element outside the order-q subgroup, while Exp(0) is 1.
func TestGtExpByGroupOrderDetectsNonSubgroupElement(t *testing.T) {
	nonMember := &fp256bnGt{*amcl.NewFP12int(2)}
	require.False(t, nonMember.Exp(groupOrderZr()).IsUnity(), "x^q must not be 1 for x outside Gt")
	require.True(t, nonMember.Exp(&common.BaseZr{Modulus: modulusBig}).IsUnity(), "x^0 must be 1")
}
