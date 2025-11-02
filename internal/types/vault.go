package types

import (
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
)

type LibType int

const (
	GG20 LibType = iota
	DKLS
	KeyImport
)

// VaultCreateRequest is a struct that represents a request to create a new vault from integration.
type VaultCreateRequest struct {
	Name               string  `json:"name" validate:"required"`
	SessionID          string  `json:"session_id" validate:"required"`
	HexEncryptionKey   string  `json:"hex_encryption_key" validate:"required"` // this is the key used to encrypt and decrypt the keygen communications
	HexChainCode       string  `json:"hex_chain_code" validate:"required"`
	LocalPartyId       string  `json:"local_party_id"`                          // when this field is empty , then server will generate a random local party id
	EncryptionPassword string  `json:"encryption_password" validate:"required"` // password used to encrypt the vault file
	Email              string  `json:"email" validate:"required"`               // this is the email of the user that the vault backup will be sent to
	LibType            LibType `json:"lib_type"`                                // this is the type of the vault
}

func isValidHexString(s string) bool {
	buf, err := hex.DecodeString(s)
	return err == nil && len(buf) == 32
}
func (req *VaultCreateRequest) IsValid() error {
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
	return nil
}

// VaultCreateResponse is a struct that represents a response to create a new vault
// integration partner need to use this information to construct a QR Code , so vultisig device can participate in the vault creation process.
type VaultCreateResponse struct {
	Name             string `json:"name"`
	SessionID        string `json:"session_id"`
	HexEncryptionKey string `json:"hex_encryption_key"`
	HexChainCode     string `json:"hex_chain_code"`
	KeygenMsg        string `json:"keygen_msg"`
}

type VaultGetResponse struct {
	Name           string `json:"name"`
	PublicKeyEcdsa string `json:"public_key_ecdsa"`
	PublicKeyEddsa string `json:"public_key_eddsa"`
	HexChainCode   string `json:"hex_chain_code"`
	LocalPartyId   string `json:"local_party_id"`
}
