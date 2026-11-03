/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"bytes"
	"fmt"
)

// SetBytesExact decodes b with setBytes (typically a gnark-crypto SetBytes
// method, which returns the number of bytes consumed) and panics unless b is
// exactly size bytes long and setBytes consumed all of it.
//
// gnark-crypto's point decoders accept buffers longer than the encoding and
// ignore the trailing bytes, and select the compressed or uncompressed format
// from the flag bits of the first byte. Requiring len(b) == size and full
// consumption makes decoding injective and pins the format to the one the
// caller asked for (see also RequireCanonicalInfinity). On-curve and subgroup checks are left to setBytes.
func SetBytesExact(b []byte, size int, setBytes func([]byte) (int, error)) {
	if len(b) != size {
		panic(fmt.Sprintf("invalid encoding: expected %d bytes, got %d", size, len(b)))
	}
	n, err := setBytes(b)
	if err != nil {
		panic(fmt.Sprintf("set bytes failed [%s]", err.Error()))
	}
	if n != size {
		panic(fmt.Sprintf("invalid encoding: wrong format (consumed %d of %d bytes)", n, size))
	}
}

// RequireCanonicalInfinity panics if a decoded identity was not given in its
// canonical encoding. gnark-crypto's BLS12 decoders also accept an all-zero
// uncompressed buffer as the identity.
func RequireCanonicalInfinity(b []byte, isInfinity bool, canonical func() []byte) {
	if isInfinity && !bytes.Equal(b, canonical()) {
		panic("invalid encoding: non-canonical point at infinity")
	}
}
