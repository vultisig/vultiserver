package chainhelper

import (
	"encoding/hex"
	"fmt"
	"strconv"

	v1 "github.com/vultisig/commondata/go/vultisig/keysign/v1"
	"google.golang.org/protobuf/proto"

	"github.com/vultisig/vultiserver/walletcore/core"
	"github.com/vultisig/vultiserver/walletcore/protos/bitcoin"
	"github.com/vultisig/vultiserver/walletcore/protos/common"
)

type ChainHelper interface {
	GetPreSignedImageHash(payload *v1.KeysignPayload) ([]string, error)
}

var _ ChainHelper = &UTXOChainHelper{}

type UTXOChainHelper struct {
	coinType core.CoinType
}

// NewUTXOChainHelper creates a new UTXOChainHelper
func NewUTXOChainHelper(coinType core.CoinType) *UTXOChainHelper {
	return &UTXOChainHelper{
		coinType: coinType,
	}
}
func (h *UTXOChainHelper) GetSwapPreSignedInputData(payload *v1.KeysignPayload, signingInput *bitcoin.SigningInput) ([]byte, error) {
	utxoSpecific := payload.GetUtxoSpecific()
	if utxoSpecific == nil {
		return nil, fmt.Errorf("missing utxo specific")
	}
	intByteFee, err := strconv.ParseInt(utxoSpecific.ByteFee, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ByteFee: %w", err)
	}
	input := signingInput
	input.ByteFee = intByteFee
	input.HashType = core.HashTypeForCoin(h.coinType)
	input.UseMaxAmount = utxoSpecific.SendMaxAmount
	for _, utxoIn := range payload.UtxoInfo {
		script := core.BitcoinScriptLockScriptForAddress(payload.Coin.Address, h.coinType)
		switch h.coinType {
		case core.CoinTypeBitcoin, core.CoinTypeLitecoin:
			keyHash := core.BitcoinScriptMatchPayToWitnessPublicKeyHash(script)
			if keyHash == nil {
				return nil, fmt.Errorf("failed to get key hash")
			}
			redeemScript := core.BitcoinScriptBuildPayToWitnessPublicKeyHash(keyHash)
			input.Scripts[hex.EncodeToString(keyHash)] = redeemScript
		case core.CoinTypeBitcoinCash, core.CoinTypeDogecoin, core.CoinTypeDash:
			keyHash := core.BitcoinScriptMatchPayToPublicKeyHash(script)
			if keyHash == nil {
				return nil, fmt.Errorf("failed to get key hash")
			}
			redeemScript := core.BitcoinScriptBuildPayToPublicKeyHash(keyHash)
			input.Scripts[hex.EncodeToString(keyHash)] = redeemScript
		default:
			return nil, fmt.Errorf("unsupported coin type: %v", h.coinType)
		}
		utxoHash, err := reverseHexString(utxoIn.Hash)
		if err != nil {
			return nil, fmt.Errorf("failed to reverse hex string,err:%w", err)
		}
		utxo := &bitcoin.UnspentTransaction{
			OutPoint: &bitcoin.OutPoint{
				Hash:     utxoHash,
				Index:    utxoIn.Index,
				Sequence: 4294967295,
			},
			Amount: utxoIn.Amount,
			Script: script,
		}
		input.Utxo = append(input.Utxo, utxo)
	}
	buf, err := proto.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal input: %w", err)
	}
	plan, err := core.AnySignerPlan(buf, h.coinType)
	if err != nil {
		return nil, fmt.Errorf("failed to get plan: %w", err)
	}
	var transactionPlan bitcoin.TransactionPlan
	if err := proto.Unmarshal(plan, &transactionPlan); err != nil {
		return nil, fmt.Errorf("failed to unmarshal plan: %w", err)
	}
	input.Plan = &transactionPlan
	return proto.Marshal(input)
}

func (h *UTXOChainHelper) getPreSignedInputData(payload *v1.KeysignPayload) (*bitcoin.SigningInput, error) {
	utxoSpecific := payload.GetUtxoSpecific()
	if utxoSpecific == nil {
		return nil, fmt.Errorf("missing utxo specific")
	}
	toAmount, err := strconv.ParseInt(payload.ToAmount, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ToAmount: %w", err)
	}
	intByteFee, err := strconv.ParseInt(utxoSpecific.ByteFee, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ByteFee: %w", err)
	}
	input := &bitcoin.SigningInput{
		HashType:      core.HashTypeForCoin(h.coinType),
		Amount:        toAmount,
		UseMaxAmount:  utxoSpecific.SendMaxAmount,
		ToAddress:     payload.ToAddress,
		ChangeAddress: payload.Coin.Address,
		ByteFee:       intByteFee,
		CoinType:      uint32(h.coinType),
		Scripts:       make(map[string][]byte),
	}
	if payload.Memo != nil && len(*payload.Memo) > 0 {
		input.OutputOpReturn = []byte(*payload.Memo)
	}
	for _, utxoIn := range payload.UtxoInfo {
		script := core.BitcoinScriptLockScriptForAddress(payload.Coin.Address, h.coinType)
		switch h.coinType {
		case core.CoinTypeBitcoin, core.CoinTypeLitecoin:
			keyHash := core.BitcoinScriptMatchPayToWitnessPublicKeyHash(script)
			if keyHash == nil {
				return nil, fmt.Errorf("failed to get key hash")
			}
			redeemScript := core.BitcoinScriptBuildPayToWitnessPublicKeyHash(keyHash)
			input.Scripts[hex.EncodeToString(keyHash)] = redeemScript
		case core.CoinTypeBitcoinCash, core.CoinTypeDogecoin, core.CoinTypeDash:
			keyHash := core.BitcoinScriptMatchPayToPublicKeyHash(script)
			if keyHash == nil {
				return nil, fmt.Errorf("failed to get key hash")
			}
			redeemScript := core.BitcoinScriptBuildPayToPublicKeyHash(keyHash)
			input.Scripts[hex.EncodeToString(keyHash)] = redeemScript
		default:
			return nil, fmt.Errorf("unsupported coin type: %v", h.coinType)
		}
		utxoHash, err := reverseHexString(utxoIn.Hash)
		if err != nil {
			return nil, fmt.Errorf("failed to reverse hex string,err:%w", err)
		}
		utxo := &bitcoin.UnspentTransaction{
			OutPoint: &bitcoin.OutPoint{
				Hash:     utxoHash,
				Index:    utxoIn.Index,
				Sequence: 4294967295,
			},
			Amount: utxoIn.Amount,
			Script: script,
		}
		input.Utxo = append(input.Utxo, utxo)
	}
	return input, nil
}
func reverseHexString(hexStr string) ([]byte, error) {
	// Decode the hex string into bytes
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}

	// Reverse the byte slice
	for i, j := 0, len(bytes)-1; i < j; i, j = i+1, j-1 {
		bytes[i], bytes[j] = bytes[j], bytes[i]
	}

	return bytes, nil
}

func (h *UTXOChainHelper) GetPreSignedImageHash(payload *v1.KeysignPayload) ([]string, error) {
	input, err := h.getPreSignedInputData(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to get pre-signed input data: %w", err)
	}
	buf, err := proto.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal input: %w", err)
	}
	plan, err := core.AnySignerPlan(buf, h.coinType)
	if err != nil {
		return nil, fmt.Errorf("failed to get plan: %w", err)
	}
	var transactionPlan bitcoin.TransactionPlan
	if err := proto.Unmarshal(plan, &transactionPlan); err != nil {
		return nil, fmt.Errorf("failed to unmarshal plan: %w", err)
	}
	input.Plan = &transactionPlan
	hashes := core.PreImageHashes(h.coinType, buf)
	var preSignOutputs bitcoin.PreSigningOutput
	if err := proto.Unmarshal(hashes, &preSignOutputs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pre-image hashes: %w", err)
	}
	if preSignOutputs.GetError() != common.SigningError_OK {
		return nil, fmt.Errorf("failed to get pre-signed image hash: %s", preSignOutputs.GetErrorMessage())
	}
	var result []string
	for _, item := range preSignOutputs.HashPublicKeys {
		result = append(result, hex.EncodeToString(item.DataHash))
	}
	return result, nil
}
