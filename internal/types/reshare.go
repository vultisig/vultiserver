package types

import (
	"fmt"

	"github.com/google/uuid"
)

type ReshareType int

const (
	Normal ReshareType = iota
	Plugin
)

// ReshareRequest is a struct that represents a request to reshare a vault
type ReshareRequest struct {
	Name               string      `json:"name"`                // name of the vault
	PublicKey          string      `json:"public_key"`          // public key ecdsa
	SessionID          string      `json:"session_id"`          // session id
	HexEncryptionKey   string      `json:"hex_encryption_key"`  // hex encryption key
	HexChainCode       string      `json:"hex_chain_code"`      // hex chain code
	LocalPartyId       string      `json:"local_party_id"`      // local party id
	OldParties         []string    `json:"old_parties"`         // old parties
	EncryptionPassword string      `json:"encryption_password"` // password used to encrypt the vault file
	Email              string      `json:"email"`
	OldResharePrefix   string      `json:"old_reshare_prefix"`
	LibType            LibType     `json:"lib_type"`
	ReshareType        ReshareType `json:"reshare_type"`
}

func (req *ReshareRequest) IsValid() error {
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
	if req.Email == "" && req.ReshareType != Plugin {
		return fmt.Errorf("email is required")
	}
	if len(req.OldParties) == 0 {
		return fmt.Errorf("old_parties is required")
	}
	return nil
}
