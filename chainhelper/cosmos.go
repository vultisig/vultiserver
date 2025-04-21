package chainhelper

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	v1 "github.com/vultisig/commondata/go/vultisig/keysign/v1"
	"google.golang.org/protobuf/proto"

	"github.com/vultisig/vultiserver/walletcore/core"
	"github.com/vultisig/vultiserver/walletcore/protos/common"
	"github.com/vultisig/vultiserver/walletcore/protos/cosmos"
	"github.com/vultisig/vultiserver/walletcore/protos/transactioncompiler"
)

type CosmosChainHelper struct {
	coinType core.CoinType
}

var _ ChainHelper = &CosmosChainHelper{}

func NewCosmosChainHelper(coinType core.CoinType) *CosmosChainHelper {
	switch coinType {
	case core.CoinTypeCosmos, core.CoinTypeKujira, core.CoinTypeDydx:
		return &CosmosChainHelper{
			coinType: coinType,
		}
	default:
		return nil
	}
}
func (h *CosmosChainHelper) GetPreSignedImageHash(payload *v1.KeysignPayload) ([]string, error) {
	input, err := h.getPreSignedInputData(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to get pre-signed input data: %w", err)
	}
	hashes := core.PreImageHashes(h.coinType, input)
	var preSigningOutput transactioncompiler.PreSigningOutput
	if err := proto.Unmarshal(hashes, &preSigningOutput); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pre-image hashes: %w", err)
	}

	if preSigningOutput.GetError() != common.SigningError_OK {
		return nil, fmt.Errorf("failed to get pre-signed image hash: %s", preSigningOutput.GetErrorMessage())
	}
	return []string{
		hex.EncodeToString(preSigningOutput.DataHash),
	}, nil
}
func (h *CosmosChainHelper) getDenom() string {
	switch h.coinType {
	case core.CoinTypeCosmos:
		return "uatom"
	case core.CoinTypeKujira:
		return "ukujira"
	case core.CoinTypeDydx:
		return "udydx"
	default:
		return ""
	}
}
func (h *CosmosChainHelper) getGasLimit() uint64 {
	switch h.coinType {
	case core.CoinTypeCosmos:
		return 200000
	case core.CoinTypeKujira:
		return 200000
	case core.CoinTypeDydx:
		return 200000
	default:
		return 0
	}
}
func (h *CosmosChainHelper) getPreSignedInputData(payload *v1.KeysignPayload) ([]byte, error) {
	cosmosSpecific := payload.GetCosmosSpecific()
	if cosmosSpecific == nil {
		return nil, errors.New("missing cosmos specific")
	}
	publicKeyBytes, err := hex.DecodeString(payload.Coin.HexPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	input := &cosmos.SigningInput{
		PublicKey:     publicKeyBytes,
		SigningMode:   cosmos.SigningMode_Protobuf,
		ChainId:       h.coinType.ChainID(),
		AccountNumber: cosmosSpecific.AccountNumber,
		Sequence:      cosmosSpecific.Sequence,
		Mode:          cosmos.BroadcastMode_SYNC,
		Messages: []*cosmos.Message{
			{
				MessageOneof: &cosmos.Message_SendCoinsMessage{
					SendCoinsMessage: &cosmos.Message_Send{
						FromAddress: payload.Coin.Address,
						Amounts: []*cosmos.Amount{
							{
								Denom:  h.getDenom(),
								Amount: payload.ToAmount,
							},
						},
						ToAddress: payload.ToAddress,
					},
				},
			},
		},
		Fee: &cosmos.Fee{
			Gas: h.getGasLimit(),
			Amounts: []*cosmos.Amount{
				{
					Denom:  h.getDenom(),
					Amount: strconv.FormatUint(cosmosSpecific.Gas, 10),
				},
			},
		},
	}
	if payload.Memo != nil && len(*payload.Memo) > 0 {
		input.Memo = *payload.Memo
	}
	return proto.Marshal(input)
}
