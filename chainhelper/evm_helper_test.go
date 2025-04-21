package chainhelper

import (
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "github.com/vultisig/commondata/go/vultisig/keysign/v1"

	"github.com/vultisig/vultiserver/walletcore/core"
)

func TestEVMChainHelper_GetPreSignedImageHash(t *testing.T) {
	h := NewEVMChainHelper(core.CoinTypeEthereum)
	memo := "voltix"
	payload := &v1.KeysignPayload{
		Coin: &v1.Coin{
			Chain:         "Ethereum",
			Ticker:        "ETH",
			Decimals:      18,
			Address:       "0xe5F238C95142be312852e864B830daADB9B7D290",
			IsNativeToken: true,
			HexPublicKey:  "03bb1adf8c0098258e4632af6c055c37135477e269b7e7eb4f600fe66d9ca9fd78",
		},
		ToAddress: "0xfA0635a1d083D0bF377EFbD48DA46BB17e0106cA",
		ToAmount:  "10000000",
		BlockchainSpecific: &v1.KeysignPayload_EthereumSpecific{
			EthereumSpecific: &v1.EthereumSpecific{
				MaxFeePerGasWei: "10",
				PriorityFee:     "1",
				Nonce:           0,
				GasLimit:        "24000",
			},
		},
		Memo:                &memo,
		VaultPublicKeyEcdsa: "023e4b76861289ad4528b33c2fd21b3a5160cd37b3294234914e21efb6ed4a452b",
		VaultLocalPartyId:   "Server-1234",
	}
	result, err := h.GetPreSignedImageHash(payload)
	// Check if the error is not nil
	if err != nil {
		t.Errorf("GetPreSignedImageHash() error = %v", err)
	}
	assert.Equal(t, 1, len(result))
	assert.Equal(t, result[0], "1e93ef6b20b01723e95128aed8786d43c7c53a12959a21ef36cf408a6d7115de")
}
