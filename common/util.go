package common

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/ulikunitz/xz"
	v1 "github.com/vultisig/commondata/go/vultisig/keygen/v1"
	vaultType "github.com/vultisig/commondata/go/vultisig/vault/v1"
	"google.golang.org/protobuf/proto"
)

// vaultV2Magic is the 4-byte header that marks a PBKDF2-encrypted vault blob.
// It matches the iOS/Android ".vult v2" wire format: 0x56 0x4C 0x54 0x02 ("VLT\x02").
// Legacy blobs (SHA-256 KDF) start with a random GCM nonce and do NOT carry this prefix.
var vaultV2Magic = [4]byte{0x56, 0x4C, 0x54, 0x02}

const (
	pbkdf2Iterations = 600_000
	pbkdf2KeyLen     = 32 // AES-256
	pbkdf2SaltLen    = 16
)

func CompressData(data []byte) ([]byte, error) {
	var compressedData bytes.Buffer
	// Create a new XZ writer.
	xzWriter, err := xz.NewWriter(&compressedData)
	if err != nil {
		return nil, fmt.Errorf("xz.NewWriter failed, err: %w", err)
	}

	// Write the input data to the XZ writer.
	_, err = xzWriter.Write(data)
	if err != nil {
		return nil, fmt.Errorf("xzWriter.Write failed, err: %w", err)
	}

	err = xzWriter.Close()
	if err != nil {
		return nil, fmt.Errorf("xzWriter.Close failed, err: %w", err)
	}

	return compressedData.Bytes(), nil
}

func DecompressData(compressedData []byte) ([]byte, error) {
	var decompressedData bytes.Buffer

	// Create a new XZ reader.
	xzReader, err := xz.NewReader(bytes.NewReader(compressedData))
	if err != nil {
		return nil, fmt.Errorf("xz.NewReader failed, err: %w", err)
	}

	// Copy the decompressed data to the buffer.
	_, err = io.Copy(&decompressedData, xzReader)
	if err != nil {
		return nil, fmt.Errorf("io.Copy failed, err: %w", err)
	}

	return decompressedData.Bytes(), nil
}

// EncryptVault encrypts vault bytes using PBKDF2-SHA256 (600k iterations) + AES-256-GCM.
//
// Wire format (matches iOS/Android ".vult v2"):
//
//	[4-byte magic: 0x56 0x4C 0x54 0x02] [16-byte random salt] [12-byte random nonce] [ciphertext] [16-byte GCM tag]
func EncryptVault(password string, vault []byte) ([]byte, error) {
	salt := make([]byte, pbkdf2SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, pbkdf2KeyLen)
	if err != nil {
		return nil, fmt.Errorf("pbkdf2 key derivation failed: %w", err)
	}

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
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Layout: magic | salt | nonce | ciphertext+tag
	out := make([]byte, 0, len(vaultV2Magic)+pbkdf2SaltLen+len(nonce)+len(vault)+16)
	out = append(out, vaultV2Magic[:]...)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, vault, nil)
	return out, nil
}

// DecryptVault decrypts a vault blob produced by EncryptVault.
// It supports both the v2 PBKDF2 format (magic prefix 0x56 0x4C 0x54 0x02) and
// the legacy SHA-256 format for backward compatibility.
func DecryptVault(password string, vault []byte) ([]byte, error) {
	if isV2Vault(vault) {
		return decryptVaultV2(password, vault)
	}
	return decryptVaultLegacy(password, vault)
}

// isV2Vault returns true when the blob starts with the v2 magic bytes.
func isV2Vault(vault []byte) bool {
	if len(vault) < len(vaultV2Magic) {
		return false
	}
	return vault[0] == vaultV2Magic[0] &&
		vault[1] == vaultV2Magic[1] &&
		vault[2] == vaultV2Magic[2] &&
		vault[3] == vaultV2Magic[3]
}

// decryptVaultV2 decrypts a PBKDF2-SHA256 (600k) + AES-256-GCM blob.
func decryptVaultV2(password string, vault []byte) ([]byte, error) {
	// minimum: magic(4) + salt(16) + nonce(12) + tag(16)
	const minLen = len(vaultV2Magic) + pbkdf2SaltLen + 12 + 16
	if len(vault) < minLen {
		return nil, fmt.Errorf("v2 vault blob too short (%d bytes)", len(vault))
	}

	offset := len(vaultV2Magic)
	salt := vault[offset : offset+pbkdf2SaltLen]
	offset += pbkdf2SaltLen

	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, pbkdf2KeyLen)
	if err != nil {
		return nil, fmt.Errorf("pbkdf2 key derivation failed: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(vault[offset:]) < nonceSize {
		return nil, fmt.Errorf("v2 vault blob nonce section too short")
	}
	nonce := vault[offset : offset+nonceSize]
	ciphertext := vault[offset+nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("v2 vault decryption failed: %w", err)
	}
	return plaintext, nil
}

// decryptVaultLegacy decrypts a legacy SHA-256(password) + AES-256-GCM blob.
// This path is kept for backward compat; new writes always use PBKDF2 (v2).
func decryptVaultLegacy(password string, vault []byte) ([]byte, error) {
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

	nonceSize := gcm.NonceSize()
	if len(vault) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := vault[:nonceSize], vault[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// IsLegacyEncryptedVaultBlob reports whether the raw AES-GCM blob uses the legacy
// SHA-256(password) derivation (i.e. it does NOT start with the v2 magic prefix).
// Callers can use this to detect blobs that need opportunistic re-encryption.
func IsLegacyEncryptedVaultBlob(blob []byte) bool {
	return !isV2Vault(blob)
}

// UpgradeVaultContainerIfLegacy inspects the inner encrypted blob inside a serialised,
// base64-encoded VaultContainer. If the blob uses the legacy SHA-256 KDF it decrypts
// with the legacy path and re-encrypts using PBKDF2-SHA256 (v2), returning the
// upgraded container bytes (base64-encoded proto). If the blob is already v2, the
// original rawBlob is returned unchanged and wasUpgraded is false.
//
// This is intended for the "re-encrypt on read" migration path: after successfully
// loading a vault, pass the raw storage bytes through this function; if wasUpgraded is
// true, write the returned upgradedBlob back to storage in place of the original.
func UpgradeVaultContainerIfLegacy(password string, rawBlob []byte) (upgradedBlob []byte, wasUpgraded bool, err error) {
	decoded, err := base64.StdEncoding.DecodeString(string(rawBlob))
	if err != nil {
		return nil, false, fmt.Errorf("base64 decode: %w", err)
	}

	var container vaultType.VaultContainer
	if err := proto.Unmarshal(decoded, &container); err != nil {
		return nil, false, fmt.Errorf("proto unmarshal VaultContainer: %w", err)
	}

	if !container.IsEncrypted {
		// Nothing to upgrade for unencrypted containers.
		return rawBlob, false, nil
	}

	innerBytes, err := base64.StdEncoding.DecodeString(container.Vault)
	if err != nil {
		return nil, false, fmt.Errorf("base64 decode inner vault: %w", err)
	}

	if !IsLegacyEncryptedVaultBlob(innerBytes) {
		// Already v2; nothing to do.
		return rawBlob, false, nil
	}

	// Legacy blob: decrypt then re-encrypt with PBKDF2.
	plaintext, err := decryptVaultLegacy(password, innerBytes)
	if err != nil {
		return nil, false, fmt.Errorf("legacy decrypt for upgrade: %w", err)
	}

	upgraded, err := EncryptVault(password, plaintext)
	if err != nil {
		return nil, false, fmt.Errorf("pbkdf2 re-encrypt for upgrade: %w", err)
	}

	container.Vault = base64.StdEncoding.EncodeToString(upgraded)

	reEncoded, err := proto.Marshal(&container)
	if err != nil {
		return nil, false, fmt.Errorf("proto marshal upgraded VaultContainer: %w", err)
	}

	return []byte(base64.StdEncoding.EncodeToString(reEncoded)), true, nil
}

func DecryptVaultFromBackup(password string, vaultBackupRaw []byte) (*vaultType.Vault, error) {
	var vaultBackup vaultType.VaultContainer
	base64DecodeVaultBackup, err := base64.StdEncoding.DecodeString(string(vaultBackupRaw))
	if err != nil {
		return nil, err
	}
	if err := proto.Unmarshal(base64DecodeVaultBackup, &vaultBackup); err != nil {
		return nil, err
	}

	vaultRaw := []byte(vaultBackup.Vault)
	if vaultBackup.IsEncrypted {
		// decrypt the vault
		vaultBytes, err := base64.StdEncoding.DecodeString(vaultBackup.Vault)
		if err != nil {
			return nil, err
		}
		vaultRaw, err = DecryptVault(password, vaultBytes)
		if err != nil {
			return nil, err
		}
	}

	var vault vaultType.Vault
	if err := proto.Unmarshal(vaultRaw, &vault); err != nil {
		return nil, err
	}

	return &vault, nil
}

// IsSubset checks if the first slice is a subset of the second slice
func IsSubset(subset, set []string) bool {
	setMap := make(map[string]bool)
	for _, v := range set {
		setMap[v] = true
	}
	for _, v := range subset {
		if !setMap[v] {
			return false
		}
	}
	return true
}

func GetVaultName(vault *vaultType.Vault) string {
	lastFourCharOfPubKey := vault.PublicKeyEcdsa[len(vault.PublicKeyEcdsa)-4:]
	partIndex := 0
	for idx, item := range vault.Signers {
		if item == vault.LocalPartyId {
			partIndex = idx
			break
		}
	}
	if vault.LibType == v1.LibType_LIB_TYPE_GG20 {
		return fmt.Sprintf("%s-%s-part%dof%d-Vultiserver.vult", vault.Name, lastFourCharOfPubKey, partIndex+1, len(vault.Signers))
	}
	return fmt.Sprintf("%s-%s-share%dof%d-Vultiserver.vult", vault.Name, lastFourCharOfPubKey, partIndex+1, len(vault.Signers))
}

func GetThreshold(value int) (int, error) {
	if value < 2 {
		return 0, errors.New("invalid input")
	}
	threshold := int(math.Ceil(float64(value)*2.0/3.0)) - 1
	return threshold, nil
}

func DecryptGCM(rawData []byte, hexEncryptKey string) ([]byte, error) {
	password, err := hex.DecodeString(hexEncryptKey)
	if err != nil {
		return nil, err
	}

	// Hash the password to create a key
	hash := sha256.Sum256([]byte(password))
	key := hash[:]

	// Create a new AES cipher using the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Use GCM (Galois/Counter Mode)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Get the nonce size
	nonceSize := gcm.NonceSize()
	if len(rawData) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract the nonce from the vault
	nonce, ciphertext := rawData[:nonceSize], rawData[nonceSize:]

	// Decrypt the vault
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
