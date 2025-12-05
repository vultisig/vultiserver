package types

import (
	"errors"
)

type KeysignRequest struct {
	PublicKey        string   `json:"public_key"`         // public key, used to identify the backup file
	Messages         []string `json:"messages"`           // Messages need to be signed
	SessionID        string   `json:"session"`            // Session ID , it should be an UUID
	HexEncryptionKey string   `json:"hex_encryption_key"` // Hex encryption key, used to encrypt the keysign messages
	DerivePath       string   `json:"derive_path"`        // Derive Path
	IsECDSA          bool     `json:"is_ecdsa"`           // indicate use ECDSA or EDDSA key to sign the messages
	VaultPassword    string   `json:"vault_password"`     // password used to decrypt the vault file
	Chain            string   `json:"chain"`              // blockchain type, e.g., BTC, ETH, etc.
}

// IsValid checks if the keysign request is valid
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
	if r.DerivePath == "" {
		return errors.New("invalid derive path")
	}

	return nil
}
