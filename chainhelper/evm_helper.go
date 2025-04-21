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

var _ ChainHelper = &EVMChainHelper{}

// EVMChainHelper is a helper for EVM chain
type EVMChainHelper struct {
	coinType core.CoinType
}

func NewEVMChainHelper(coinType core.CoinType) *EVMChainHelper {
	return &EVMChainHelper{
		coinType: coinType,
	}
}
func (h *EVMChainHelper) getPreSignedInputData(payload *v1.KeysignPayload) ([]byte, error) {
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
	transfer := &ethereum.Transaction_Transfer{
		Amount: big.NewInt(toAmount).Bytes(),
	}
	if payload.Memo != nil && len(*payload.Memo) > 0 {
		transfer.Data = []byte(*payload.Memo)
	}
	tx := &ethereum.Transaction{
		TransactionOneof: &ethereum.Transaction_Transfer_{
			Transfer: transfer,
		},
	}

	input := &ethereum.SigningInput{
		ChainId:               big.NewInt(int64(intChainID)).Bytes(),
		Nonce:                 big.NewInt(specific.Nonce).Bytes(),
		TxMode:                ethereum.TransactionMode_Enveloped,
		GasLimit:              big.NewInt(gasLimit).Bytes(),
		MaxInclusionFeePerGas: big.NewInt(priorityFee).Bytes(),
		MaxFeePerGas:          big.NewInt(maxFeePerGasWei).Bytes(),
		ToAddress:             payload.ToAddress,
		Transaction:           tx,
	}
	return proto.Marshal(input)
}
func (h *EVMChainHelper) GetPreSignedImageHash(payload *v1.KeysignPayload) ([]string, error) {
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
