/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"math/big"

	"github.com/IBM/mathlib/driver"
)

type CurveBase struct {
	Modulus *big.Int
}

func (c *CurveBase) ModNeg(a1, m driver.Zr) driver.Zr {
	res := new(big.Int).Sub(m.(*BaseZr).Int, a1.(*BaseZr).Int)
	res.Mod(res, m.(*BaseZr).Int)

	return &BaseZr{Int: res, Modulus: c.Modulus}
}

func (p *CurveBase) GroupOrder() driver.Zr {
	return &BaseZr{Int: p.Modulus, Modulus: p.Modulus}
}
