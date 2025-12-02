package types

import (
	"fmt"

	"github.com/google/uuid"
)

// KeyImportRequest is a struct that represents a request to import a key into a vault.
type KeyImportRequest struct {
	Name               string   `json:"name" validate:"required"`
	SessionID          string   `json:"session_id" validate:"required"`
	HexEncryptionKey   string   `json:"hex_encryption_key" validate:"required"` // this is the key used to encrypt and decrypt the keygen communications
	HexChainCode       string   `json:"hex_chain_code" validate:"required"`
	LocalPartyId       string   `json:"local_party_id"`                          // when this field is empty , then server will generate a random local party id
	EncryptionPassword string   `json:"encryption_password" validate:"required"` // password used to encrypt the vault file
	Email              string   `json:"email" validate:"required"`               // this is the email of the user that the vault backup will be sent to
	Chains             []string `json:"chains" validate:"required"`              // chains to import the key for
}

func (req *KeyImportRequest) IsValid() error {
	if req.Name == "" {
		return fmt.Errorf("name is required")
	}
	if req.SessionID == "" {
		return fmt.Errorf("session_id is required")
	}
	if _, err := uuid.Parse(req.SessionID); err != nil {
		return fmt.Errorf("session_id is not valid")
	}

	if req.HexEncryptionKey == "" {
		return fmt.Errorf("hex_encryption_key is required")
	}
	if !isValidHexString(req.HexEncryptionKey) {
		return fmt.Errorf("hex_encryption_key is not valid")
	}
	if req.HexChainCode == "" {
		return fmt.Errorf("hex_chain_code is required")
	}
	if !isValidHexString(req.HexChainCode) {
		return fmt.Errorf("hex_chain_code is not valid")
	}
	if req.EncryptionPassword == "" {
		return fmt.Errorf("encryption_password is required")
	}
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if len(req.Chains) == 0 {
		return fmt.Errorf("at least one chain is required")
	}
	return nil
}
