// Copyright IBM Corp. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

// gen_vectors_test.go regenerates the known-answer vectors embedded in
// compat_test.go.  It is excluded from the normal test build by the
// //go:build ignore constraint above.
//
// To regenerate vectors, temporarily remove (or comment out) the
// //go:build ignore line, then run:
//
//	cd driver/gurvy && go test -run TestGenVectors -v
//
// Restore the build constraint afterwards so this file is not compiled
// during normal test runs.
//
// The output is valid Go struct-literal rows that can be pasted directly
// into the vector tables in compat_test.go.

package gurvy

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/hash_to_curve"
)

func TestGenVectors(t *testing.T) {
	fmt.Println("// ---- Hash vectors -------------------------------------------------------")
	fmt.Println("// Paste into hashVectors in compat_test.go")
	for i := 0; i < 8; i++ {
		msg := []byte(string(rune(i)) + "test_hash_msg")
		domain := []byte("test_hash_domain")
		gU, err := Hash(msg, domain, 2, sha256.New)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("{%q, %q, \"%x\", \"%x\"},\n",
			msg, domain, gU[0].Bytes(), gU[1].Bytes())
	}

	fmt.Println()
	fmt.Println("// ---- SwuMapG1BE vectors -------------------------------------------------")
	fmt.Println("// Paste into swuMapG1BEVectors in compat_test.go")
	for i := 0; i < 8; i++ {
		msg := []byte(fmt.Sprintf("swu_input_%d", i))
		domain := []byte("swu_test_domain")
		gU, err := Hash(msg, domain, 1, sha256.New)
		if err != nil {
			t.Fatal(err)
		}
		u := &gU[0]
		gX, gY := SwuMapG1BE(u)
		fmt.Printf("{\"%x\", \"%x\", \"%x\"},\n",
			u.Bytes(), gX.Bytes(), gY.Bytes())
	}

	fmt.Println()
	fmt.Println("// ---- IsogenyMapG1 smoke vectors ----------------------------------------")
	fmt.Println("// Paste into isogenyMapG1SmokeVectors in compat_test.go")
	for i := 0; i < 4; i++ {
		msg := []byte(fmt.Sprintf("iso_input_%d", i))
		domain := []byte("iso_test_domain")
		gU, err := Hash(msg, domain, 1, sha256.New)
		if err != nil {
			t.Fatal(err)
		}
		u := &gU[0]
		gX, gY := SwuMapG1BE(u)
		isoX := *gX
		isoY := *gY
		hash_to_curve.G1Isogeny(&isoX, &isoY)
		fmt.Printf("{\"%x\", \"%x\", \"%x\"},\n",
			u.Bytes(), isoX.Bytes(), isoY.Bytes())
	}

	fmt.Println()
	fmt.Println("// ---- HashToG1GenericBESwu vectors ---------------------------------------")
	fmt.Println("// Paste into hashToG1Vectors in compat_test.go")
	for i := 0; i < 8; i++ {
		msg := []byte(string(rune(i)) + "test_message_compat")
		domain := []byte("test_domain_compat")
		gPoint, err := HashToG1GenericBESwu(msg, domain, sha256.New)
		if err != nil {
			t.Fatal(err)
		}
		raw := gPoint.RawBytes()
		fmt.Printf("{%q, %q, \"%x\"},\n", msg, domain, raw[:])
	}
}
