package common

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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

func EncryptVault(password string, vault []byte) ([]byte, error) {
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

	// Create a nonce. Nonce size is specified by GCM
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Seal encrypts and authenticates plaintext
	ciphertext := gcm.Seal(nonce, nonce, vault, nil)
	return ciphertext, nil
}

func DecryptVault(password string, vault []byte) ([]byte, error) {
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
	if len(vault) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract the nonce from the vault
	nonce, ciphertext := vault[:nonceSize], vault[nonceSize:]

	// Decrypt the vault
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
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
			return nil, ErrWrongPassword
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
