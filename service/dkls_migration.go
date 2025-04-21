package service

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	keygenType "github.com/vultisig/commondata/go/vultisig/keygen/v1"
	vaultType "github.com/vultisig/commondata/go/vultisig/vault/v1"
	"github.com/vultisig/mobile-tss-lib/tss"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/vultisig/vultiserver/relay"
)

func rightPadWithZeros(input string, length int) string {
	if len(input) >= length {
		return input
	}
	paddingLen := length - len(input)
	return input + strings.Repeat("0", paddingLen)
}
func (t *DKLSTssService) ProceeMigration(vault *vaultType.Vault,
	sessionID string,
	hexEncryptionKey string,
	encryptionPassword string,
	email string) error {
	serverURL := t.cfg.Relay.Server
	relayClient := relay.NewRelayClient(serverURL)
	if vault.Name == "" {
		return fmt.Errorf("vault name is empty")
	}
	if vault.LocalPartyId == "" {
		return fmt.Errorf("local party id is empty")
	}
	if vault.HexChainCode == "" {
		return fmt.Errorf("hex chain code is empty")
	}
	var keyShareEcdsa string
	var keyShareEdDSA string
	for _, item := range vault.KeyShares {
		if item.PublicKey == vault.PublicKeyEcdsa {
			keyShareEcdsa = item.Keyshare
		}
		if item.PublicKey == vault.PublicKeyEddsa {
			keyShareEdDSA = item.Keyshare
		}
	}
	if keyShareEcdsa == "" {
		return fmt.Errorf("ecdsa keyshare is empty")
	}
	if keyShareEdDSA == "" {
		return fmt.Errorf("eddsa keyshare is empty")
	}
	localUIEcdsa, err := tss.GetLocalUIEcdsa(keyShareEcdsa)
	if err != nil {
		return fmt.Errorf("fail to get local UI Ecdsa: %w", err)
	}
	localUIEddsa, err := tss.GetLocalUIEddsa(keyShareEdDSA)
	if err != nil {
		return fmt.Errorf("failed to get local UI EdDSA: %w", err)
	}
	localUIEcdsa = rightPadWithZeros(localUIEcdsa, 64)
	localUIEddsa = rightPadWithZeros(localUIEddsa, 64)
	localPartyId := vault.LocalPartyId
	// Let's register session here
	if err := relayClient.RegisterSession(sessionID, localPartyId); err != nil {
		return fmt.Errorf("failed to register session: %w", err)
	}
	// wait longer for keygen start
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	partiesJoined, err := relayClient.WaitForSessionStart(ctx, sessionID)
	t.logger.WithFields(logrus.Fields{
		"sessionID":      sessionID,
		"parties_joined": partiesJoined,
	}).Info("Session started")

	if err != nil {
		return fmt.Errorf("failed to wait for session start: %w", err)
	}

	// create ECDSA key
	publicKeyECDSA, chainCodeECDSA, err := t.migrateWithRetry(vault.PublicKeyEcdsa,
		vault.HexChainCode,
		localUIEcdsa,
		sessionID,
		hexEncryptionKey,
		localPartyId,
		false,
		partiesJoined)
	if err != nil {
		return fmt.Errorf("failed to keygen ECDSA: %w", err)
	}
	time.Sleep(500 * time.Millisecond)
	// create EdDSA key
	publicKeyEdDSA, _, err := t.migrateWithRetry(
		vault.PublicKeyEddsa,
		vault.HexChainCode,
		localUIEddsa,
		sessionID,
		hexEncryptionKey,
		localPartyId, true, partiesJoined)
	if err != nil {
		return fmt.Errorf("failed to keygen EdDSA: %w", err)
	}

	if err := relayClient.CompleteSession(sessionID, localPartyId); err != nil {
		t.logger.WithFields(logrus.Fields{
			"session": sessionID,
			"error":   err,
		}).Error("Failed to complete session")
	}

	if isCompleted, err := relayClient.CheckCompletedParties(sessionID, partiesJoined); err != nil || !isCompleted {
		t.logger.WithFields(logrus.Fields{
			"sessionID":   sessionID,
			"isCompleted": isCompleted,
			"error":       err,
		}).Error("Failed to check completed parties")
		return fmt.Errorf("failed to check completed parties: %w", err)
	}
	if t.backup == nil {
		return nil
	}

	ecdsaKeyShare, err := t.localStateAccessor.GetLocalCacheState(publicKeyECDSA)
	if err != nil {
		return fmt.Errorf("failed to get local sate: %w", err)
	}
	if ecdsaKeyShare == "" {
		return fmt.Errorf("failed to get ecdsa keyshare")
	}
	eddsaKeyShare, err := t.localStateAccessor.GetLocalCacheState(publicKeyEdDSA)
	if err != nil {
		return fmt.Errorf("failed to get local sate: %w", err)
	}
	if eddsaKeyShare == "" {
		return fmt.Errorf("failed to get eddsa keyshare")
	}
	newVault := &vaultType.Vault{
		Name:           vault.Name,
		PublicKeyEcdsa: publicKeyECDSA,
		PublicKeyEddsa: publicKeyEdDSA,
		Signers:        partiesJoined,
		CreatedAt:      timestamppb.Now(),
		HexChainCode:   chainCodeECDSA,
		KeyShares: []*vaultType.Vault_KeyShare{
			{
				PublicKey: publicKeyECDSA,
				Keyshare:  ecdsaKeyShare,
			},
			{
				PublicKey: publicKeyEdDSA,
				Keyshare:  eddsaKeyShare,
			},
		},
		LocalPartyId:  vault.LocalPartyId,
		LibType:       keygenType.LibType_LIB_TYPE_DKLS,
		ResharePrefix: "",
	}
	return t.backup.SaveVaultAndScheduleEmail(newVault, encryptionPassword, email)
}

func (t *DKLSTssService) migrateWithRetry(publicKey string,
	hexChainCode string,
	localUI string,
	sessionID string,
	hexEncryptionKey string,
	localPartyID string,
	isEdDSA bool,
	keygenCommittee []string) (string, string, error) {
	for i := 0; i < 3; i++ {
		publicKey, chainCode, err := t.migrate(publicKey,
			hexChainCode,
			localUI,
			sessionID,
			hexEncryptionKey,
			localPartyID,
			isEdDSA,
			keygenCommittee, i)
		if err != nil {
			t.logger.WithFields(logrus.Fields{
				"session_id":       sessionID,
				"local_party_id":   localPartyID,
				"keygen_committee": keygenCommittee,
				"attempt":          i,
			}).Error(err)
			time.Sleep(50 * time.Millisecond)
			continue
		} else {
			return publicKey, chainCode, nil
		}
	}
	return "", "", fmt.Errorf("fail to keygen after max retry")
}

func (t *DKLSTssService) migrate(
	publicKey string,
	hexChainCode string,
	localUI string,
	sessionID string,
	hexEncryptionKey string,
	localPartyID string,
	isEdDSA bool,
	keygenCommittee []string,
	attempt int) (string, string, error) {
	t.logger.WithFields(logrus.Fields{
		"session_id":       sessionID,
		"local_party_id":   localPartyID,
		"keygen_committee": keygenCommittee,
		"publicKey":        publicKey,
		"hexChainCode":     hexChainCode,
		"attempt":          attempt,
	}).Info("migrate")
	t.isKeygenFinished.Store(false)
	relayClient := relay.NewRelayClient(t.cfg.Relay.Server)
	mpcKeygenWrapper := t.GetMPCKeygenWrapper(isEdDSA)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// retrieve the setup Message
	encryptedEncodedSetupMsg, err := relayClient.WaitForSetupMessage(ctx, sessionID, "")
	if err != nil {
		return "", "", fmt.Errorf("failed to get setup message: %w", err)
	}
	setupMessageBytes, err := t.decodeDecryptMessage(encryptedEncodedSetupMsg, hexEncryptionKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode setup message: %w", err)
	}
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode public key")
	}
	chainCodeBytes, err := hex.DecodeString(hexChainCode)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode chain code")
	}
	localUIBytes, err := hex.DecodeString(localUI)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode local UI")
	}
	handle, err := mpcKeygenWrapper.MigrateSessionFromSetup(setupMessageBytes,
		[]byte(localPartyID),
		publicKeyBytes,
		chainCodeBytes,
		localUIBytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to create session from setup message: %w", err)
	}
	defer func() {
		if err := mpcKeygenWrapper.KeygenSessionFree(handle); err != nil {
			t.logger.Error("failed to free keygen session", "error", err)
		}
	}()
	wg := &sync.WaitGroup{}
	wg.Add(2)
	go func() {
		if err := t.processKeygenOutbound(handle, sessionID, hexEncryptionKey, keygenCommittee, localPartyID, isEdDSA, wg); err != nil {
			t.logger.Error("failed to process keygen outbound", "error", err)
		}
	}()
	publicKey, chainCode, err := t.processKeygenInbound(handle, sessionID, hexEncryptionKey, isEdDSA, localPartyID, wg)
	wg.Wait()
	return publicKey, chainCode, err
}
