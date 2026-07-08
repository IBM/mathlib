/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package math

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Golden vectors captured from the original github.com/kilic/bls12-381 backend
// before it was replaced by the gnark-crypto (gurvy) backend. They pin the byte
// representation of the BLS12_381 and BLS12_381_BBS curves so the migration is
// provably output-compatible. The only operations that differ between the two
// curve IDs are HashToG1 / HashToG1WithDomain (the BBS variant uses the
// big-endian-sign Simplified SWU map).
//
// The fixed scalar below is used for the group-element multiplications.
var goldenScalar = []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44}

type goldenVec struct {
	genG1Mul           string
	genG2Mul           string
	genGtExp           string
	hashToG1           string
	hashToG1WithDomain string
	hashToG1CompDomain string
	hashToG2           string
}

var golden = map[CurveID]goldenVec{
	BLS12_381: {
		genG1Mul:           "091a87a08856fc7d22775e13cf6d7472c327189422a5cf1e3c75cf11a80f63e87ab51a2678fc49b73d3489339743f01c073388aa8847dea668fbb393f34c2d89a2bdfec536eb898eca87c64bc324d61e7ec323ae37a5189e14d918136f5adaf7",
		genG2Mul:           "087d66f44564f5d109f024146d2c1f2a8e8d3a61092e79412a740f8cc7ee51994578bd228844d265ab2fdc1eda9ee052063069ec05711ca84a4f58eeedee779f85e0d03021aac92bc855e42abccdbc135b2df215bab0ccc6190fad3905b5a5b2108b14e74e788fcfe12a6d26b72f7f0468861ddf6b90138f39105c062c201fd08dcdf1b86c1ef1023441e2972e3a2e87068d5ae2f1e19dd5a8a8aaf45a410a9af22989b5eff0be66c8e37498cae3575d0e1c0e124a4dce05098b35e6f327bdf9",
		genGtExp:           "031c4404a493b639fda9e6dcce1f15e2f972ae3ef6fdda302c9ad1c04ede609ae5c3cbaa532cf75b643931a56e756ceb16ce1dcebd47fb1585a519e2ebe3965c1bdc33a5ece1dd02f716903b3498c284c1ddcaa7a56bbf4e4fa0e0645e899b9214c6b4927ad130cd74dd8758849eb9a6ebfb01f82b53bf2f9f5f768725cc7a18dd1debbb699e192a9facebb546d4f1c107686aa37bac547bf8aff86fad7f76e01dde85c1be37e879248059952cc8d6e310dffcc89ddb596b53504380c2cee69a04fc1442ac76d799b5e145faa29641d4ed74479d6a1ee241a0340c4d9d43dadd4032c9f5f36a2b80e86021dee4e22f4e16b55c6801cc71877674cdb4a9a4370dcae197ee1a7620b8aa4c48035fe487ea8150981a20d104c1ae31e6b5402d288817f034523ecd57165a170f37eb584a581441d24798d06fbeb9b18c2359fafe8f9d0595dc8d12681993481b43d6fe39de16fb64b8c9a3ed5f183b9f83c2bd4b769784c1262cb9564086edf169aaf554f192f73b3ccf0b8a99cca5fe0dbf56e27d078314f3923b1d7076f780bf3269a37e916a8e4effff186a2e59a82a8eed165bd7ea21d95e49479e1af841037786a5f50a8fb585f5d35616690827861c79e60169829b62680145b766035a2473c7c441a12f0569868771d62d6e3d5dfaf8b84403a5772182532b4dd796347608e67f26f7acea7ba6e55bf75c9525924e9ee03f69e88558f3f8174049f1293f26f27da018666a67fc23e1bfdeb219cc19d8db4fec7f4d7b89437320ed920e13ae45ca3adfacde37f68397ad20007bc85208c5ee",
		hashToG1:           "02a54fad2d2ce3d6d993ba0f64c8e4b7ac3f5f34f118e8f42a24470486e0987282d89c16508f7b21cda6432ab19ba8fa180cff3784fb7fe6a78a53e430a4151be844abc07bb911d9a393c9131dd8216d1e79f254b15792fbaefa9f5a96e7afd6",
		hashToG1WithDomain: "073e516c8d035a9768fce91a4429e0cb4b2aa8286ef3e7cb20e5b008e6415346c069ac8e42e91b0c85f55ade80c5592c060dbaf70a32dcb8dc1fd7550f8bca2f237a56e4490e414a86fb9348c7048d6e3d4ac52ac8c42ec3767f5d0ed4f40228",
		hashToG1CompDomain: "873e516c8d035a9768fce91a4429e0cb4b2aa8286ef3e7cb20e5b008e6415346c069ac8e42e91b0c85f55ade80c5592c",
		hashToG2:           "152a5103cb577d1b5c01be1621ecb3b9d8fdd095c5b6cb2efe53667001cd389e5631af2568bc7185831764bb4b8828da0468a3c807fb0e2262bc1a6c0024c3e2e51c5ad160c5a43c4de769bd9d61857ac3b83dae0a860328b6f42f6b621453530e8522a85b79654fd83b79609ef52b9ad4be13bd5f55e0711f577a50704e3e549bbe4257b3c717175c6dbc3f23e031081674c02a1ff7114b9e810a8dd76744f0df559801981f6a8386716a90d15c6573fb562f91da83e8a843912e5d673399e7",
	},
	BLS12_381_BBS: {
		genG1Mul:           "091a87a08856fc7d22775e13cf6d7472c327189422a5cf1e3c75cf11a80f63e87ab51a2678fc49b73d3489339743f01c073388aa8847dea668fbb393f34c2d89a2bdfec536eb898eca87c64bc324d61e7ec323ae37a5189e14d918136f5adaf7",
		genG2Mul:           "087d66f44564f5d109f024146d2c1f2a8e8d3a61092e79412a740f8cc7ee51994578bd228844d265ab2fdc1eda9ee052063069ec05711ca84a4f58eeedee779f85e0d03021aac92bc855e42abccdbc135b2df215bab0ccc6190fad3905b5a5b2108b14e74e788fcfe12a6d26b72f7f0468861ddf6b90138f39105c062c201fd08dcdf1b86c1ef1023441e2972e3a2e87068d5ae2f1e19dd5a8a8aaf45a410a9af22989b5eff0be66c8e37498cae3575d0e1c0e124a4dce05098b35e6f327bdf9",
		genGtExp:           "031c4404a493b639fda9e6dcce1f15e2f972ae3ef6fdda302c9ad1c04ede609ae5c3cbaa532cf75b643931a56e756ceb16ce1dcebd47fb1585a519e2ebe3965c1bdc33a5ece1dd02f716903b3498c284c1ddcaa7a56bbf4e4fa0e0645e899b9214c6b4927ad130cd74dd8758849eb9a6ebfb01f82b53bf2f9f5f768725cc7a18dd1debbb699e192a9facebb546d4f1c107686aa37bac547bf8aff86fad7f76e01dde85c1be37e879248059952cc8d6e310dffcc89ddb596b53504380c2cee69a04fc1442ac76d799b5e145faa29641d4ed74479d6a1ee241a0340c4d9d43dadd4032c9f5f36a2b80e86021dee4e22f4e16b55c6801cc71877674cdb4a9a4370dcae197ee1a7620b8aa4c48035fe487ea8150981a20d104c1ae31e6b5402d288817f034523ecd57165a170f37eb584a581441d24798d06fbeb9b18c2359fafe8f9d0595dc8d12681993481b43d6fe39de16fb64b8c9a3ed5f183b9f83c2bd4b769784c1262cb9564086edf169aaf554f192f73b3ccf0b8a99cca5fe0dbf56e27d078314f3923b1d7076f780bf3269a37e916a8e4effff186a2e59a82a8eed165bd7ea21d95e49479e1af841037786a5f50a8fb585f5d35616690827861c79e60169829b62680145b766035a2473c7c441a12f0569868771d62d6e3d5dfaf8b84403a5772182532b4dd796347608e67f26f7acea7ba6e55bf75c9525924e9ee03f69e88558f3f8174049f1293f26f27da018666a67fc23e1bfdeb219cc19d8db4fec7f4d7b89437320ed920e13ae45ca3adfacde37f68397ad20007bc85208c5ee",
		hashToG1:           "15f112904d3f2d00e89660a94c7159c1ba4063c0bb2f60d844c64becafc99d4885c22d3796b9043e6579e83bb233e2c00e67dada768a94b3052df7925908bf5ecbb4a0f9cf11c1130b89ab8e5523a116af195e887b0e6f75d51b8bd25f16aa10",
		hashToG1WithDomain: "16022c85ce70d7133c3b7fa532b3f73b2875f367d7a1715c0d69eff0852372e67a8cee6ec58b92fdff906c18e446a30214492bc6380b98d0d22b0b50853cc13d60e1adcf01ba48502cfedf51b9e0b2834a1fc2f177e9e715d2d358e87a96a917",
		hashToG1CompDomain: "b6022c85ce70d7133c3b7fa532b3f73b2875f367d7a1715c0d69eff0852372e67a8cee6ec58b92fdff906c18e446a302",
		hashToG2:           "152a5103cb577d1b5c01be1621ecb3b9d8fdd095c5b6cb2efe53667001cd389e5631af2568bc7185831764bb4b8828da0468a3c807fb0e2262bc1a6c0024c3e2e51c5ad160c5a43c4de769bd9d61857ac3b83dae0a860328b6f42f6b621453530e8522a85b79654fd83b79609ef52b9ad4be13bd5f55e0711f577a50704e3e549bbe4257b3c717175c6dbc3f23e031081674c02a1ff7114b9e810a8dd76744f0df559801981f6a8386716a90d15c6573fb562f91da83e8a843912e5d673399e7",
	},
}

// TestGoldenKilicCompat verifies that the gnark-crypto backends now wired to the
// BLS12_381 and BLS12_381_BBS curve IDs reproduce, byte-for-byte, the outputs of
// the original kilic backend they replaced.
func TestGoldenKilicCompat(t *testing.T) {
	for id, want := range golden {
		t.Run(CurveIDToString(id), func(t *testing.T) {
			c := Curves[id]
			z := c.NewZrFromBytes(goldenScalar)

			assert.Equal(t, want.genG1Mul, hex.EncodeToString(c.GenG1.Mul(z).Bytes()), "GenG1.Mul")
			assert.Equal(t, want.genG2Mul, hex.EncodeToString(c.GenG2.Mul(z).Bytes()), "GenG2.Mul")
			assert.Equal(t, want.genGtExp, hex.EncodeToString(c.GenGt.Exp(z).Bytes()), "GenGt.Exp")
			assert.Equal(t, want.hashToG1, hex.EncodeToString(c.HashToG1([]byte("Chase!")).Bytes()), "HashToG1")

			h := c.HashToG1WithDomain([]byte("CD"), []byte("EF"))
			assert.Equal(t, want.hashToG1WithDomain, hex.EncodeToString(h.Bytes()), "HashToG1WithDomain")
			assert.Equal(t, want.hashToG1CompDomain, hex.EncodeToString(h.Compressed()), "HashToG1WithDomain compressed")

			assert.Equal(t, want.hashToG2, hex.EncodeToString(c.HashToG2([]byte("Chase!")).Bytes()), "HashToG2")
		})
	}

	// Sanity: the BBS HashToG1 output must differ from the standard one,
	// confirming the big-endian-sign SWU map is actually in effect.
	require.NotEqual(t,
		golden[BLS12_381].hashToG1,
		golden[BLS12_381_BBS].hashToG1,
		"BBS HashToG1 should differ from standard HashToG1")
}
