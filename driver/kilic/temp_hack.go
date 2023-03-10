/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kilic

import (
	"fmt"
	bls12377 "kilic/bls12-377"
	"unsafe"

	"github.com/IBM/mathlib/driver"
	bls12381 "github.com/kilic/bls12-381"
)

func bls12381tobls12377(p *bls12381.PointG1) *bls12377.PointG1 {
	return (*bls12377.PointG1)(unsafe.Pointer(p))
}

func (c *Bls12_377) HashToG1(data []byte) driver.G1 {
	g1 := bls12381.NewG1()
	p, err := g1.HashToCurve(data, domain)
	if err != nil {
		panic(fmt.Sprintf("HashToCurve failed [%s]", err.Error()))
	}

	return &bls12_377G1{bls12381tobls12377(p)}
}
