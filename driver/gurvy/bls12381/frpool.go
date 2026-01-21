/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bls12381

import (
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// frElements is a shared *bls12381.FrElement{} memory pool
var frElements frElementPool

var _frElementPool = sync.Pool{
	New: func() interface{} {
		return new(fr.Element)
	},
}

type frElementPool struct{}

func (frElementPool) Get() *fr.Element {
	return _frElementPool.Get().(*fr.Element)
}

func (frElementPool) Put(v *fr.Element) {
	if v == nil {
		panic("put called with nil value")
	}
	// reset v before putting it back
	v.SetZero()
	_frElementPool.Put(v)
}
