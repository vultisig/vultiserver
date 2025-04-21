package chainhelper

import (
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "github.com/vultisig/commondata/go/vultisig/keysign/v1"

	"github.com/vultisig/vultiserver/walletcore/core"
)

func TestUTXOHelper_BTC(t *testing.T) {
	utxoHelper := NewUTXOChainHelper(core.CoinTypeBitcoin)
	assert.NotNil(t, utxoHelper)
	memo := "voltix"
	payload := &v1.KeysignPayload{
		Coin: &v1.Coin{
			Chain:           "Bitcoin",
			Ticker:          "BTC",
			Address:         "bc1qj9q4nsl3q7z6t36un08j6t7knv5v3cwnnstaxu",
			Decimals:        8,
			PriceProviderId: "",
			IsNativeToken:   true,
			HexPublicKey:    "026724d27f668b88513c925360ba5c5888cc03641eccbe70e6d85023e7c511b969",
		},
		ToAddress: "bc1q4e4y3g85dtkx0yp3l2flj2nmugf23c9wwtjwu5",
		ToAmount:  "10000000",
		BlockchainSpecific: &v1.KeysignPayload_UtxoSpecific{
			UtxoSpecific: &v1.UTXOSpecific{
				ByteFee:       "20",
				SendMaxAmount: false,
			},
		},
		UtxoInfo: []*v1.UtxoInfo{
			{
				Hash:   "631fad872ac6bea810cf6073f02e6cbd121cac83193b79f381f711ce93b531f0",
				Amount: 193796,
				Index:  1,
			},
		},
		Memo:                &memo,
		SwapPayload:         nil,
		Erc20ApprovePayload: nil,
		VaultPublicKeyEcdsa: "ECDSAKey",
		VaultLocalPartyId:   "localPartyID",
	}
	result, err := utxoHelper.GetPreSignedImageHash(payload)
	t.Logf("result: %v", result)
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result), 1)
	assert.Equal(t, result[0], "14249cd992ccb9f8fb0e9f24dfe4437231819c6e02c52959b939a65eb533cbd4")
}

func TestUTXOHelper_BCH(t *testing.T) {
	utxoHelper := NewUTXOChainHelper(core.CoinTypeBitcoinCash)
	assert.NotNil(t, utxoHelper)
	memo := "voltix"
	payload := &v1.KeysignPayload{
		Coin: &v1.Coin{
			Chain:           "BitcoinCash",
			Ticker:          "BCH",
			Address:         "qrfc9f9ta67l6x3ufcv8fdz83228r2vtcqmnul7jgx",
			Decimals:        8,
			PriceProviderId: "",
			IsNativeToken:   true,
			HexPublicKey:    "0333bda0119776bd3f22b5dc6b1083bd3f5993b4d4b10b26db2dc55b919a5bb587",
		},
		ToAddress: "bitcoincash:qqxjcn4u4fgxvclqyaprkem3hptm3nf5yq3ryq70ry",
		ToAmount:  "1000000",
		BlockchainSpecific: &v1.KeysignPayload_UtxoSpecific{
			UtxoSpecific: &v1.UTXOSpecific{
				ByteFee:       "20",
				SendMaxAmount: false,
			},
		},
		UtxoInfo: []*v1.UtxoInfo{
			{
				Hash:   "71787a90556de944fcea8d8ff7478e535092638a68491b60b5661dfd871c40e4",
				Amount: 10000000,
				Index:  0,
			},
		},
		Memo:                &memo,
		SwapPayload:         nil,
		Erc20ApprovePayload: nil,
		VaultPublicKeyEcdsa: "ECDSAKey",
		VaultLocalPartyId:   "localPartyID",
	}
	result, err := utxoHelper.GetPreSignedImageHash(payload)
	t.Logf("result: %v", result)
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result), 1)
	assert.Equal(t, result[0], "195b256774ca393f2e9812478abf6958076d0ff7d427dc958d35a9f7ffe7439b")
}
