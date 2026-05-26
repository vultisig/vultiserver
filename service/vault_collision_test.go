package service

import (
	"encoding/base64"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	vaultType "github.com/vultisig/commondata/go/vultisig/vault/v1"

	"github.com/vultisig/vultiserver/common"
)

const testPassword = "hunter2"

// buildEncryptedVaultFile builds an encrypted vault backup file (base64-encoded
// proto) matching the format produced by SaveVaultAndScheduleEmail.
func buildEncryptedVaultFile(t *testing.T, v *vaultType.Vault, password string) []byte {
	t.Helper()
	vaultData, err := proto.Marshal(v)
	if err != nil {
		t.Fatalf("proto.Marshal(vault): %v", err)
	}
	encrypted, err := common.EncryptVault(password, vaultData)
	if err != nil {
		t.Fatalf("common.EncryptVault: %v", err)
	}
	container := &vaultType.VaultContainer{
		Version:     1,
		Vault:       base64.StdEncoding.EncodeToString(encrypted),
		IsEncrypted: true,
	}
	containerBytes, err := proto.Marshal(container)
	if err != nil {
		t.Fatalf("proto.Marshal(container): %v", err)
	}
	return []byte(base64.StdEncoding.EncodeToString(containerBytes))
}

func makeVault(ecdsa, eddsa, chainCode, partyID string) *vaultType.Vault {
	return &vaultType.Vault{
		Name:           "test-vault",
		PublicKeyEcdsa: ecdsa,
		PublicKeyEddsa: eddsa,
		HexChainCode:   chainCode,
		LocalPartyId:   partyID,
		CreatedAt:      timestamppb.Now(),
	}
}

// TestDetectVaultCollision_NoExistingFile verifies that passing nil / empty
// file data returns nil (no collision for a new registration).
func TestDetectVaultCollision_NoExistingFile(t *testing.T) {
	// We model "file not found" by never calling detectVaultCollision —
	// checkVaultCollision returns nil on GetFile error. Here we test the pure
	// helper with a nil slice, which DecryptVaultFromBackup will fail to parse,
	// triggering the "can't decrypt → allow" path. That's a slightly different
	// path from "file not found" but both result in nil.
	//
	// The "file not found" case is covered by the nil-input test.
	incoming := makeVault("ecdsa-01", "eddsa-01", "chaincode01", "Server-12345")
	err := detectVaultCollision(incoming, testPassword, nil, nil)
	if err != nil {
		t.Fatalf("expected nil for no existing file, got: %v", err)
	}
}

// TestDetectVaultCollision_IdenticalMetadata verifies that an idempotent
// re-write (all metadata identical) is allowed.
func TestDetectVaultCollision_IdenticalMetadata(t *testing.T) {
	existing := makeVault("ecdsa-01", "eddsa-01", "chaincode01", "Server-12345")
	incoming := makeVault("ecdsa-01", "eddsa-01", "chaincode01", "Server-12345")
	fileData := buildEncryptedVaultFile(t, existing, testPassword)

	err := detectVaultCollision(incoming, testPassword, fileData, nil)
	if err != nil {
		t.Fatalf("expected nil for identical metadata, got: %v", err)
	}
}

// TestDetectVaultCollision_EddsaPubkeyDrifted verifies that a different EdDSA
// pubkey triggers ErrVaultCollision.
func TestDetectVaultCollision_EddsaPubkeyDrifted(t *testing.T) {
	existing := makeVault("ecdsa-01", "eddsa-ORIGINAL", "chaincode01", "Server-12345")
	incoming := makeVault("ecdsa-01", "eddsa-DRIFTED", "chaincode01", "Server-12345")
	fileData := buildEncryptedVaultFile(t, existing, testPassword)

	err := detectVaultCollision(incoming, testPassword, fileData, nil)
	if !errors.Is(err, ErrVaultCollision) {
		t.Fatalf("expected ErrVaultCollision for eddsa drift, got: %v", err)
	}
}

// TestDetectVaultCollision_ChainCodeDrifted verifies that a different chain
// code triggers ErrVaultCollision.
func TestDetectVaultCollision_ChainCodeDrifted(t *testing.T) {
	existing := makeVault("ecdsa-01", "eddsa-01", "chaincode-ORIGINAL", "Server-12345")
	incoming := makeVault("ecdsa-01", "eddsa-01", "chaincode-DRIFTED", "Server-12345")
	fileData := buildEncryptedVaultFile(t, existing, testPassword)

	err := detectVaultCollision(incoming, testPassword, fileData, nil)
	if !errors.Is(err, ErrVaultCollision) {
		t.Fatalf("expected ErrVaultCollision for chain code drift, got: %v", err)
	}
}

// TestDetectVaultCollision_PartyIdDrifted verifies that a different
// local_party_id (server signer) triggers ErrVaultCollision.
func TestDetectVaultCollision_PartyIdDrifted(t *testing.T) {
	existing := makeVault("ecdsa-01", "eddsa-01", "chaincode01", "Server-11111")
	incoming := makeVault("ecdsa-01", "eddsa-01", "chaincode01", "Server-99999")
	fileData := buildEncryptedVaultFile(t, existing, testPassword)

	err := detectVaultCollision(incoming, testPassword, fileData, nil)
	if !errors.Is(err, ErrVaultCollision) {
		t.Fatalf("expected ErrVaultCollision for party_id drift, got: %v", err)
	}
}

// TestDetectVaultCollision_WrongPassword verifies that when the existing vault
// can't be decrypted (wrong password), we conservatively allow the overwrite.
func TestDetectVaultCollision_WrongPassword(t *testing.T) {
	existing := makeVault("ecdsa-01", "eddsa-01", "chaincode01", "Server-12345")
	incoming := makeVault("ecdsa-01", "eddsa-DRIFTED", "chaincode01", "Server-99999")
	// Encrypt with a DIFFERENT password so decryption with testPassword fails.
	fileData := buildEncryptedVaultFile(t, existing, "different-password")

	err := detectVaultCollision(incoming, testPassword, fileData, nil)
	if err != nil {
		t.Fatalf("expected nil (conservatively allow) when existing can't be decrypted, got: %v", err)
	}
}
