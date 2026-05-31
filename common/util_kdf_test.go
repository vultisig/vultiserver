package common

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"testing"

	vaultType "github.com/vultisig/commondata/go/vultisig/vault/v1"
	"google.golang.org/protobuf/proto"
)

// legacyEncrypt reproduces the old SHA-256(password) + AES-256-GCM encryption
// used by the server prior to this migration. Used only in tests to produce legacy
// blobs for backward-compat verification.
func legacyEncrypt(password string, plaintext []byte) ([]byte, error) {
	hash := sha256.Sum256([]byte(password))
	key := hash[:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// TestEncryptVaultV2Format verifies that EncryptVault produces a v2 (PBKDF2) blob.
func TestEncryptVaultV2Format(t *testing.T) {
	blob, err := EncryptVault("hunter2", []byte("payload"))
	if err != nil {
		t.Fatalf("EncryptVault: %v", err)
	}
	if !isV2Vault(blob) {
		t.Errorf("EncryptVault should produce a v2 blob (magic prefix); got %x", blob[:min(4, len(blob))])
	}
	if IsLegacyEncryptedVaultBlob(blob) {
		t.Error("IsLegacyEncryptedVaultBlob should return false for a v2 blob")
	}
}

// TestEncryptDecryptRoundTrip verifies the new PBKDF2 encrypt→decrypt path.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	plaintext := []byte("secret vault data")
	password := "correct-horse-battery-staple"

	blob, err := EncryptVault(password, plaintext)
	if err != nil {
		t.Fatalf("EncryptVault: %v", err)
	}

	got, err := DecryptVault(password, blob)
	if err != nil {
		t.Fatalf("DecryptVault: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, plaintext)
	}
}

// TestDecryptVaultWrongPassword verifies that decryption with wrong password fails.
func TestDecryptVaultWrongPassword(t *testing.T) {
	blob, err := EncryptVault("correct", []byte("data"))
	if err != nil {
		t.Fatalf("EncryptVault: %v", err)
	}
	if _, err := DecryptVault("wrong", blob); err == nil {
		t.Error("expected decryption to fail with wrong password")
	}
}

// TestLegacyEncryptDecrypt verifies backward compat: SHA-256-derived blobs still decrypt.
func TestLegacyEncryptDecrypt(t *testing.T) {
	plaintext := []byte("legacy vault payload")
	password := "legacy-password"

	// Produce a legacy blob via the internal helper (mimics old EncryptVault behaviour).
	legacy, err := legacyEncrypt(password, plaintext)
	if err != nil {
		t.Fatalf("legacyEncrypt: %v", err)
	}

	if !IsLegacyEncryptedVaultBlob(legacy) {
		t.Error("IsLegacyEncryptedVaultBlob should return true for a legacy blob")
	}

	got, err := DecryptVault(password, legacy)
	if err != nil {
		t.Fatalf("DecryptVault (legacy): %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("legacy round-trip mismatch: got %q, want %q", got, plaintext)
	}
}

// TestUpgradeVaultContainerIfLegacy verifies the opportunistic re-encryption path.
func TestUpgradeVaultContainerIfLegacy(t *testing.T) {
	plaintext := []byte("vault proto bytes")
	password := "upgrade-test-pw"

	// Build a legacy-encrypted VaultContainer (as written by the old server).
	legacy, err := legacyEncrypt(password, plaintext)
	if err != nil {
		t.Fatalf("legacyEncrypt: %v", err)
	}
	container := &vaultType.VaultContainer{
		Version:     1,
		Vault:       base64.StdEncoding.EncodeToString(legacy),
		IsEncrypted: true,
	}
	containerBytes, err := proto.Marshal(container)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	rawBlob := []byte(base64.StdEncoding.EncodeToString(containerBytes))

	upgraded, wasUpgraded, err := UpgradeVaultContainerIfLegacy(password, rawBlob)
	if err != nil {
		t.Fatalf("UpgradeVaultContainerIfLegacy: %v", err)
	}
	if !wasUpgraded {
		t.Error("expected wasUpgraded=true for a legacy container")
	}

	// The upgraded blob must decode as a v2 inner blob.
	decoded, err := base64.StdEncoding.DecodeString(string(upgraded))
	if err != nil {
		t.Fatalf("base64 decode upgraded: %v", err)
	}
	var upgradedContainer vaultType.VaultContainer
	if err := proto.Unmarshal(decoded, &upgradedContainer); err != nil {
		t.Fatalf("proto.Unmarshal upgraded: %v", err)
	}
	innerBytes, err := base64.StdEncoding.DecodeString(upgradedContainer.Vault)
	if err != nil {
		t.Fatalf("base64 decode inner: %v", err)
	}
	if !isV2Vault(innerBytes) {
		t.Errorf("upgraded inner blob should be v2; got prefix %x", innerBytes[:min(4, len(innerBytes))])
	}

	// The upgraded blob must still decrypt to the original plaintext.
	got, err := DecryptVault(password, innerBytes)
	if err != nil {
		t.Fatalf("DecryptVault on upgraded: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("upgraded blob plaintext mismatch: got %q, want %q", got, plaintext)
	}
}

// TestUpgradeVaultContainerIfLegacy_AlreadyV2 verifies no-op on v2 containers.
func TestUpgradeVaultContainerIfLegacy_AlreadyV2(t *testing.T) {
	plaintext := []byte("already new data")
	password := "already-new-pw"

	v2Blob, err := EncryptVault(password, plaintext)
	if err != nil {
		t.Fatalf("EncryptVault: %v", err)
	}
	container := &vaultType.VaultContainer{
		Version:     1,
		Vault:       base64.StdEncoding.EncodeToString(v2Blob),
		IsEncrypted: true,
	}
	containerBytes, err := proto.Marshal(container)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	rawBlob := []byte(base64.StdEncoding.EncodeToString(containerBytes))

	_, wasUpgraded, err := UpgradeVaultContainerIfLegacy(password, rawBlob)
	if err != nil {
		t.Fatalf("UpgradeVaultContainerIfLegacy: %v", err)
	}
	if wasUpgraded {
		t.Error("expected wasUpgraded=false for an already-v2 container")
	}
}

// TestEncryptVaultDifferentSalts verifies that two encryptions of the same plaintext
// produce different ciphertexts (random salt + nonce per call).
func TestEncryptVaultDifferentSalts(t *testing.T) {
	plaintext := []byte("same data")
	password := "same-password"

	b1, err := EncryptVault(password, plaintext)
	if err != nil {
		t.Fatalf("EncryptVault (1): %v", err)
	}
	b2, err := EncryptVault(password, plaintext)
	if err != nil {
		t.Fatalf("EncryptVault (2): %v", err)
	}
	if bytes.Equal(b1, b2) {
		t.Error("two encryptions of identical plaintext produced identical ciphertext — salt/nonce not random")
	}
}

// min returns the smaller of two ints (Go 1.21+ built-in; keep local for clarity).
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
