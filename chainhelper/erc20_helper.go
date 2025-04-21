package chainhelper

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"

	v1 "github.com/vultisig/commondata/go/vultisig/keysign/v1"
	"google.golang.org/protobuf/proto"

	"github.com/vultisig/vultiserver/walletcore/core"
	"github.com/vultisig/vultiserver/walletcore/protos/common"
	"github.com/vultisig/vultiserver/walletcore/protos/ethereum"
	"github.com/vultisig/vultiserver/walletcore/protos/transactioncompiler"
)

var _ ChainHelper = &ERC20ChainHelper{}

type ERC20ChainHelper struct {
	coinType core.CoinType
}

func NewERC20ChainHelper(coinType core.CoinType) *ERC20ChainHelper {
	return &ERC20ChainHelper{
		coinType: coinType,
	}
}
func (h *ERC20ChainHelper) getPreSignedInputData(payload *v1.KeysignPayload) ([]byte, error) {
	intChainID, err := strconv.Atoi(h.coinType.ChainID())
	if err != nil {
		return nil, fmt.Errorf("failed to parse ChainID: %w", err)
	}
	specific := payload.GetEthereumSpecific()
	if specific == nil {
		return nil, fmt.Errorf("missing ethereum specific")
	}
	gasLimit, err := strconv.ParseInt(specific.GasLimit, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse GasLimit: %w", err)
	}
	maxFeePerGasWei, err := strconv.ParseInt(specific.MaxFeePerGasWei, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MaxFeePerGasWei: %w", err)
	}
	priorityFee, err := strconv.ParseInt(specific.PriorityFee, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PriorityFee: %w", err)
	}
	toAmount, err := strconv.ParseInt(payload.ToAmount, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ToAmount: %w", err)
	}
	transfer := &ethereum.Transaction_ERC20Transfer{
		To:     payload.ToAddress,
		Amount: big.NewInt(toAmount).Bytes(),
	}

	tx := &ethereum.Transaction{
		TransactionOneof: &ethereum.Transaction_Erc20Transfer{
			Erc20Transfer: transfer,
		},
	}

	input := &ethereum.SigningInput{
		ChainId:               big.NewInt(int64(intChainID)).Bytes(),
		Nonce:                 big.NewInt(specific.Nonce).Bytes(),
		TxMode:                ethereum.TransactionMode_Enveloped,
		GasLimit:              big.NewInt(gasLimit).Bytes(),
		MaxInclusionFeePerGas: big.NewInt(priorityFee).Bytes(),
		MaxFeePerGas:          big.NewInt(maxFeePerGasWei).Bytes(),
		ToAddress:             payload.Coin.ContractAddress,
		Transaction:           tx,
	}
	return proto.Marshal(input)
}
func (h *ERC20ChainHelper) GetPreSignedImageHash(payload *v1.KeysignPayload) ([]string, error) {
	data, err := h.getPreSignedInputData(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to get pre-signed input data: %w", err)
	}
	hashes := core.PreImageHashes(h.coinType, data)
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
