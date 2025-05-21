package service

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	keygenType "github.com/vultisig/commondata/go/vultisig/keygen/v1"
	vaultType "github.com/vultisig/commondata/go/vultisig/vault/v1"
	"golang.org/x/exp/slices"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/vultisig/vultiserver/common"
	"github.com/vultisig/vultiserver/relay"
)

func (t *DKLSTssService) ProcessReshare(vault *vaultType.Vault,
	sessionID string,
	hexEncryptionKey string,
	encryptionPassword string,
	email string, noBackup bool) error {
	if vault.Name == "" {
		return fmt.Errorf("vault name is empty")
	}
	if vault.LocalPartyId == "" {
		return fmt.Errorf("local party id is empty")
	}
	if vault.HexChainCode == "" {
		return fmt.Errorf("hex chain code is empty")
	}
	localPartyID := vault.LocalPartyId
	client := relay.NewRelayClient(t.cfg.Relay.Server)
	// Let's register session here
	if err := client.RegisterSession(sessionID, vault.LocalPartyId); err != nil {
		return fmt.Errorf("failed to register session: %w", err)
	}
	// wait longer for keygen start
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	partiesJoined, err := client.WaitForSessionStart(ctx, sessionID)
	t.logger.WithFields(logrus.Fields{
		"session":        sessionID,
		"parties_joined": partiesJoined,
	}).Info("Session started")
	if err != nil {
		return fmt.Errorf("failed to wait for session start: %w", err)
	}
	if len(partiesJoined) == 0 {
		return fmt.Errorf("keygen committee is empty")
	}
	t.logger.Infof("start reshare ecdsa")
	ecdsaPubkey, chainCodeECDSA, err := t.reshareWithRetry(vault, sessionID, hexEncryptionKey, partiesJoined, vault.PublicKeyEcdsa, false)
	if err != nil {
		return fmt.Errorf("failed to reshare ECDSA: %w", err)
	}
	t.logger.Infof("start reshare eddsa")
	eddsaPubkey, _, err := t.reshareWithRetry(vault, sessionID, hexEncryptionKey, partiesJoined, vault.PublicKeyEddsa, true)
	if err != nil {
		return fmt.Errorf("failed to reshare EDDSA: %w", err)
	}
	if err := client.CompleteSession(sessionID, localPartyID); err != nil {
		t.logger.WithFields(logrus.Fields{
			"session": sessionID,
			"error":   err,
		}).Error("Failed to complete session")
	}

	if isCompleted, err := client.CheckCompletedParties(sessionID, partiesJoined); err != nil || !isCompleted {
		t.logger.WithFields(logrus.Fields{
			"sessionID":   sessionID,
			"isCompleted": isCompleted,
			"error":       err,
		}).Error("Failed to check completed parties")
		return fmt.Errorf("failed to check completed parties: %w", err)
	}
	if t.backup == nil {
		t.logger.Infof("Backup is disabled")
		return nil
	}
	if noBackup {
		t.logger.Infof("Backup is disabled")
		return nil
	}
	ecdsaKeyShare, err := t.localStateAccessor.GetLocalCacheState(ecdsaPubkey)
	if err != nil {
		return fmt.Errorf("failed to get local sate: %w", err)
	}
	if ecdsaKeyShare == "" {
		return fmt.Errorf("failed to get ecdsa keyshare")
	}
	eddsaKeyShare, err := t.localStateAccessor.GetLocalCacheState(eddsaPubkey)
	if err != nil {
		return fmt.Errorf("failed to get local sate: %w", err)
	}
	if eddsaKeyShare == "" {
		return fmt.Errorf("failed to get eddsa keyshare")
	}
	newVault := &vaultType.Vault{
		Name:           vault.Name,
		PublicKeyEcdsa: ecdsaPubkey,
		PublicKeyEddsa: eddsaPubkey,
		Signers:        partiesJoined,
		CreatedAt:      timestamppb.Now(),
		HexChainCode:   chainCodeECDSA,
		KeyShares: []*vaultType.Vault_KeyShare{
			{
				PublicKey: ecdsaPubkey,
				Keyshare:  ecdsaKeyShare,
			},
			{
				PublicKey: eddsaPubkey,
				Keyshare:  eddsaKeyShare,
			},
		},
		LocalPartyId:  vault.LocalPartyId,
		LibType:       keygenType.LibType_LIB_TYPE_DKLS,
		ResharePrefix: "",
	}
	return t.backup.SaveVaultAndScheduleEmail(newVault, encryptionPassword, email)
}
func (t *DKLSTssService) reshareWithRetry(vault *vaultType.Vault,
	sessionID string,
	hexEncryptionKey string,
	keygenCommittee []string,
	publicKey string,
	isEdDSA bool,
) (string, string, error) {
	for attempt := 0; attempt < 3; attempt++ {
		newPublicKey, chainCode, err := t.reshare(vault, sessionID, hexEncryptionKey, keygenCommittee, publicKey, isEdDSA, attempt)
		if err == nil {
			return newPublicKey, chainCode, nil
		}
		t.logger.Error("failed to reshare", "error", err)
	}
	return "", "", fmt.Errorf("failed to reshare after 3 attempts")
}
func (t *DKLSTssService) reshare(vault *vaultType.Vault,
	sessionID string,
	hexEncryptionKey string,
	keygenCommittee []string,
	publicKey string,
	isEdDSA bool,
	attempt int,
) (string, string, error) {
	t.logger.
		WithFields(logrus.Fields{
			"session_id": sessionID,
			"public_key": publicKey,
		}).Infof("Reshare attempt %d,", attempt)
	mpcWrapper := t.GetMPCKeygenWrapper(isEdDSA)
	var keyshareHandle Handle
	t.isKeygenFinished.Store(false)
	if len(publicKey) > 0 {
		// we need to get the shares
		keyshare, err := t.localStateAccessor.GetLocalState(publicKey)
		if err != nil {
			return "", "", fmt.Errorf("failed to get keyshare: %w", err)
		}
		keyshareBytes, err := base64.StdEncoding.DecodeString(keyshare)
		if err != nil {
			return "", "", fmt.Errorf("failed to decode keyshare: %w", err)
		}
		keyshareHandle, err = mpcWrapper.KeyshareFromBytes(keyshareBytes)
		if err != nil {
			return "", "", fmt.Errorf("failed to create keyshare from bytes: %w", err)
		}
		defer func() {
			if err := mpcWrapper.KeyshareFree(keyshareHandle); err != nil {
				t.logger.Error("failed to free keyshare", "error", err)
			}
		}()
	}
	localPartyID := vault.LocalPartyId
	client := relay.NewRelayClient(t.cfg.Relay.Server)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// retrieve the setup Message
	additionalHeader := ""
	if isEdDSA {
		additionalHeader = "eddsa"
	}
	encryptedEncodedSetupMsg, err := client.WaitForSetupMessage(ctx, sessionID, additionalHeader)
	if err != nil {
		return "", "", fmt.Errorf("failed to get setup message: %w", err)
	}
	setupMessageBytes, err := t.decodeDecryptMessage(encryptedEncodedSetupMsg, hexEncryptionKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode setup message: %w", err)
	}
	handle, err := mpcWrapper.QcSessionFromSetup(setupMessageBytes,
		localPartyID,
		keyshareHandle)
	if err != nil {
		return "", "", fmt.Errorf("failed to create session from setup message: %w", err)
	}
	isInNewCommittee := slices.Contains(keygenCommittee, vault.LocalPartyId)
	wg := &sync.WaitGroup{}
	wg.Add(2)
	go func() {
		if err := t.processQcOutbound(handle, sessionID, hexEncryptionKey, keygenCommittee, localPartyID, isEdDSA, wg); err != nil {
			t.logger.Error("failed to process keygen outbound", "error", err)
		}
	}()
	publicKey, chainCode, err := t.processQcInbound(handle, sessionID, hexEncryptionKey, isEdDSA, localPartyID, isInNewCommittee, wg)
	wg.Wait()
	return publicKey, chainCode, err
}

func (t *DKLSTssService) processQcOutbound(handle Handle,
	sessionID string,
	hexEncryptionKey string,
	parties []string,
	localPartyID string,
	isEdDSA bool,
	wg *sync.WaitGroup) error {
	defer wg.Done()
	messenger := relay.NewMessenger(t.cfg.Relay.Server, sessionID, hexEncryptionKey, true, "")
	mpcKeygenWrapper := t.GetMPCKeygenWrapper(isEdDSA)
	defer func() {
		t.logger.Infof("finish processQcOutbound")
	}()
	for {
		outbound, err := mpcKeygenWrapper.QcSessionOutputMessage(handle)
		if err != nil {
			t.logger.Error("failed to get output message", "error", err)
		}
		if len(outbound) == 0 {
			if t.isKeygenFinished.Load() {
				// we are finished
				return nil
			}
			time.Sleep(time.Millisecond * 100)
			continue
		}
		encodedOutbound := base64.StdEncoding.EncodeToString(outbound)
		for i := 0; i < len(parties); i++ {
			receiver, err := mpcKeygenWrapper.QcSessionMessageReceiver(handle, outbound, i)
			if err != nil {
				t.logger.Errorf("failed to get receiver message err: %s", err)
			}
			if len(receiver) == 0 {
				break
			}

			t.logger.Infoln("Sending message to", receiver)
			// send the message to the receiver
			if err := messenger.Send(localPartyID, receiver, encodedOutbound); err != nil {
				t.logger.Errorf("failed to send message: %v", err)
			}
		}
	}
}
func (t *DKLSTssService) decodeDecryptMessage(body string, hexEncryptionKey string) ([]byte, error) {
	decodedBody, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("fail to decode message: %w", err)
	}
	rawBody, err := common.DecryptGCM(decodedBody, hexEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("fail to decrypt message: %w", err)
	}

	inboundBody, err := base64.StdEncoding.DecodeString(string(rawBody))
	if err != nil {
		return nil, fmt.Errorf("fail to decode inbound message: %w", err)
	}
	return inboundBody, nil
}
func (t *DKLSTssService) processQcInbound(handle Handle,
	sessionID string,
	hexEncryptionKey string,
	isEdDSA bool,
	localPartyID string,
	isInCommittee bool,
	wg *sync.WaitGroup) (string, string, error) {
	defer wg.Done()
	var messageCache sync.Map
	mpcWrapper := t.GetMPCKeygenWrapper(isEdDSA)
	relayClient := relay.NewRelayClient(t.cfg.Relay.Server)
	start := time.Now()
	for {
		select {
		case <-time.After(time.Millisecond * 100):
			if time.Since(start) > time.Minute {
				// set isKeygenFinished to true , so the other go routine can be stopped
				t.isKeygenFinished.Store(true)
				return "", "", TssKeyGenTimeout
			}
			messages, err := relayClient.DownloadMessages(sessionID, localPartyID, "")
			if err != nil {
				t.logger.Error("fail to get messages", "error", err)
				continue
			}
			for _, message := range messages {
				if message.From == localPartyID {
					t.logger.Error("Received message from self, skipping")
					continue
				}
				cacheKey := fmt.Sprintf("%s-%s-%s", sessionID, localPartyID, message.Hash)
				if _, found := messageCache.Load(cacheKey); found {
					t.logger.Infof("Message already applied, skipping,hash: %s", message.Hash)
					continue
				}
				inboundBody, err := t.decodeDecryptMessage(message.Body, hexEncryptionKey)
				if err != nil {
					t.logger.Error("fail to decode message", "error", err)
					continue
				}

				isFinished, err := mpcWrapper.QcSessionInputMessage(handle, inboundBody)
				if err != nil {
					t.logger.Error("fail to apply input message", "error", err)
					continue
				}
				t.logger.Infof("apply inbound message to dkls: %s, from: %s, %d", message.Hash, message.From, message.SequenceNo)
				if err := relayClient.DeleteMessageFromServer(sessionID, localPartyID, message.Hash, ""); err != nil {
					t.logger.Error("fail to delete message", "error", err)
				}
				if isFinished {
					t.logger.Infoln("Reshare finished")
					defer func() {
						t.isKeygenFinished.Store(true)
					}()
					result, err := mpcWrapper.QcSessionFinish(handle)
					if err != nil {
						t.logger.Error("fail to finish reshare", "error", err)
						return "", "", err
					}
					if !isInCommittee {
						t.logger.Infof("Reshare finished, but local party is not in committee")
						return "", "", nil
					}
					buf, err := mpcWrapper.KeyshareToBytes(result)
					if err != nil {
						t.logger.Error("fail to convert keyshare to bytes", "error", err)
						return "", "", err
					}
					encodedShare := base64.StdEncoding.EncodeToString(buf)
					publicKeyBytes, err := mpcWrapper.KeysharePublicKey(result)
					if err != nil {
						t.logger.Error("fail to get public key", "error", err)
						return "", "", err
					}
					encodedPublicKey := hex.EncodeToString(publicKeyBytes)
					t.logger.Infof("Public key: %s", encodedPublicKey)
					chainCode := ""
					if !isEdDSA {
						chainCodeBytes, err := mpcWrapper.KeyshareChainCode(result)
						if err != nil {
							t.logger.Error("fail to get chain code", "error", err)
							return "", "", err
						}
						chainCode = hex.EncodeToString(chainCodeBytes)
					}
					if err := t.localStateAccessor.SaveLocalState(encodedPublicKey, encodedShare); err != nil {
						t.logger.Error("fail to save local state", "error", err)
						return "", "", err
					}
					return encodedPublicKey, chainCode, nil
				}
			}
		}
	}
}
