package types

import (
	"errors"
	"strings"
)

type ZcashSaplingNote struct {
	NoteData    string `json:"note_data"`
	WitnessData string `json:"witness_data"`
}

type ZcashSaplingOutput struct {
	Address string `json:"address"`
	Amount  uint64 `json:"amount"`
}

type ZcashSaplingContext struct {
	Notes   []ZcashSaplingNote   `json:"notes"`
	Outputs []ZcashSaplingOutput `json:"outputs"`
	Fee     uint64               `json:"fee"`
	Alphas  []string             `json:"alphas"`
	Sighash string               `json:"sighash"`
}

type KeysignRequest struct {
	PublicKey        string               `json:"public_key"`
	Messages         []string             `json:"messages"`
	SessionID        string               `json:"session"`
	HexEncryptionKey string               `json:"hex_encryption_key"`
	DerivePath       string               `json:"derive_path"`
	IsECDSA          bool                 `json:"is_ecdsa"`
	VaultPassword    string               `json:"vault_password"`
	Chain            string               `json:"chain"`
	Mldsa            bool                 `json:"mldsa"`
	ZcashSapling     *ZcashSaplingContext `json:"zcash_sapling,omitempty"`
}

func (r KeysignRequest) IsValid() error {
	if r.PublicKey == "" {
		return errors.New("invalid public key ECDSA")
	}
	if len(r.Messages) == 0 {
		return errors.New("invalid messages")
	}
	if r.SessionID == "" {
		return errors.New("invalid session")
	}
	if r.HexEncryptionKey == "" {
		return errors.New("invalid hex encryption key")
	}
	if r.DerivePath == "" &&
		!strings.EqualFold(r.Chain, "ZcashSapling") &&
		!strings.EqualFold(r.Chain, "Monero") {
		return errors.New("invalid derive path")
	}
	if strings.EqualFold(r.Chain, "ZcashSapling") {
		if r.ZcashSapling == nil {
			return errors.New("zcash_sapling context is required")
		}
		if r.ZcashSapling.Sighash == "" {
			return errors.New("zcash_sapling sighash is required")
		}
	}

	return nil
}
