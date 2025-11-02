package service

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/vultisig/vultiserver/config"
	"github.com/vultisig/vultiserver/internal/types"
	"github.com/vultisig/vultiserver/relay"
	"github.com/vultisig/vultiserver/storage"
)

var TssKeyGenTimeout = errors.New("keygen timeout")

type DKLSTssService struct {
	cfg                config.Config
	messenger          *relay.MessengerImp
	logger             *logrus.Logger
	localStateAccessor *relay.LocalStateAccessorImp
	isKeygenFinished   *atomic.Bool
	isKeysignFinished  *atomic.Bool
	blockStorage       *storage.BlockStorage
	backup             VaultOperation
}

func NewDKLSTssService(cfg config.Config,
	blockStorage *storage.BlockStorage,
	localStateAccessor *relay.LocalStateAccessorImp,
	backupInterface VaultOperation) (*DKLSTssService, error) {
	return &DKLSTssService{
		cfg:                cfg,
		logger:             logrus.WithField("service", "dkls").Logger,
		isKeygenFinished:   &atomic.Bool{},
		isKeysignFinished:  &atomic.Bool{},
		blockStorage:       blockStorage,
		localStateAccessor: localStateAccessor,
		backup:             backupInterface,
	}, nil
}

func (t *DKLSTssService) GetMPCKeygenWrapper(isEdDSA bool) *MPCWrapperImp {
	return NewMPCWrapperImp(isEdDSA)
}

func (t *DKLSTssService) ProceeDKLSKeygen(req types.VaultCreateRequest) (string, string, error) {
	serverURL := t.cfg.Relay.Server
	relayClient := relay.NewRelayClient(serverURL)

	// Let's register session here
	if err := relayClient.RegisterSessionWithRetry(req.SessionID, req.LocalPartyId); err != nil {
		return "", "", fmt.Errorf("failed to register session: %w", err)
	}
	// wait longer for keygen start
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	partiesJoined, err := relayClient.WaitForSessionStart(ctx, req.SessionID)
	t.logger.WithFields(logrus.Fields{
		"sessionID":      req.SessionID,
		"parties_joined": partiesJoined,
	}).Info("Session started")

	if err != nil {
		return "", "", fmt.Errorf("failed to wait for session start: %w", err)
	}
	// create ECDSA key
	publicKeyECDSA, chainCodeECDSA, err := t.keygenWithRetry(req.SessionID, req.HexEncryptionKey, req.LocalPartyId, false, partiesJoined)
	if err != nil {
		return "", "", fmt.Errorf("failed to keygen ECDSA: %w", err)
	}
	time.Sleep(500 * time.Millisecond)
	// create EdDSA key
	publicKeyEdDSA, _, err := t.keygenWithRetry(req.SessionID, req.HexEncryptionKey, req.LocalPartyId, true, partiesJoined)
	if err != nil {
		return "", "", fmt.Errorf("failed to keygen EdDSA: %w", err)
	}

	if err := relayClient.CompleteSession(req.SessionID, req.LocalPartyId); err != nil {
		t.logger.WithFields(logrus.Fields{
			"session": req.SessionID,
			"error":   err,
		}).Error("Failed to complete session")
	}

	if isCompleted, err := relayClient.CheckCompletedParties(req.SessionID, partiesJoined); err != nil || !isCompleted {
		t.logger.WithFields(logrus.Fields{
			"sessionID":   req.SessionID,
			"isCompleted": isCompleted,
			"error":       err,
		}).Error("Failed to check completed parties")
		return "", "", fmt.Errorf("failed to check completed parties: %w", err)
	}
	if t.backup == nil {
		return publicKeyECDSA, publicKeyEdDSA, nil
	}

	err = t.backup.BackupVault(req, partiesJoined, publicKeyECDSA, publicKeyEdDSA, chainCodeECDSA, t.localStateAccessor)
	if err != nil {
		return "", "", fmt.Errorf("failed to backup vault: %w", err)
	}
	return publicKeyECDSA, publicKeyEdDSA, nil
}

func (t *DKLSTssService) ProcessDKLSKeyImport(req types.VaultCreateRequest) (string, string, error) {
	serverURL := t.cfg.Relay.Server
	relayClient := relay.NewRelayClient(serverURL)

	// Let's register session here
	if err := relayClient.RegisterSessionWithRetry(req.SessionID, req.LocalPartyId); err != nil {
		return "", "", fmt.Errorf("failed to register session: %w", err)
	}
	// wait longer for keygen start
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	partiesJoined, err := relayClient.WaitForSessionStart(ctx, req.SessionID)
	t.logger.WithFields(logrus.Fields{
		"sessionID":      req.SessionID,
		"parties_joined": partiesJoined,
	}).Info("Session started")

	if err != nil {
		return "", "", fmt.Errorf("failed to wait for session start: %w", err)
	}
	// create ECDSA key
	publicKeyECDSA, chainCodeECDSA, err := t.keyImportWithRetry(req.SessionID, req.HexEncryptionKey, req.LocalPartyId, false, partiesJoined)
	if err != nil {
		return "", "", fmt.Errorf("failed to KeyImport ECDSA: %w", err)
	}
	time.Sleep(500 * time.Millisecond)
	// create EdDSA key
	publicKeyEdDSA, _, err := t.keyImportWithRetry(req.SessionID, req.HexEncryptionKey, req.LocalPartyId, true, partiesJoined)
	if err != nil {
		return "", "", fmt.Errorf("failed to KeyImport EdDSA: %w", err)
	}

	if err := relayClient.CompleteSession(req.SessionID, req.LocalPartyId); err != nil {
		t.logger.WithFields(logrus.Fields{
			"session": req.SessionID,
			"error":   err,
		}).Error("Failed to complete session")
	}

	if isCompleted, err := relayClient.CheckCompletedParties(req.SessionID, partiesJoined); err != nil || !isCompleted {
		t.logger.WithFields(logrus.Fields{
			"sessionID":   req.SessionID,
			"isCompleted": isCompleted,
			"error":       err,
		}).Error("Failed to check completed parties")
		return "", "", fmt.Errorf("failed to check completed parties: %w", err)
	}
	if t.backup == nil {
		return publicKeyECDSA, publicKeyEdDSA, nil
	}

	err = t.backup.BackupVault(req, partiesJoined, publicKeyECDSA, publicKeyEdDSA, chainCodeECDSA, t.localStateAccessor)
	if err != nil {
		return "", "", fmt.Errorf("failed to backup vault: %w", err)
	}
	return publicKeyECDSA, publicKeyEdDSA, nil
}

func (t *DKLSTssService) keyImportWithRetry(sessionID string,
	hexEncryptionKey string,
	localPartyID string,
	isEdDSA bool,
	keygenCommittee []string) (string, string, error) {
	for i := 0; i < 3; i++ {
		publicKey, chainCode, err := t.keyImport(sessionID, hexEncryptionKey, localPartyID, isEdDSA, keygenCommittee, i)
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

func (t *DKLSTssService) keyImport(sessionID string,
	hexEncryptionKey string,
	localPartyID string,
	isEdDSA bool,
	keygenCommittee []string,
	attempt int) (string, string, error) {
	t.logger.WithFields(logrus.Fields{
		"session_id":       sessionID,
		"local_party_id":   localPartyID,
		"keygen_committee": keygenCommittee,
		"attempt":          attempt,
	}).Info("Keygen")
	t.isKeygenFinished.Store(false)
	relayClient := relay.NewRelayClient(t.cfg.Relay.Server)
	mpcKeygenWrapper := t.GetMPCKeygenWrapper(isEdDSA)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// retrieve the setup Message
	additionalHeader := ""
	if isEdDSA {
		additionalHeader = "eddsa_key_import"
	}
	encryptedEncodedSetupMsg, err := relayClient.WaitForSetupMessage(ctx, sessionID, additionalHeader)
	if err != nil {
		return "", "", fmt.Errorf("failed to get setup message: %w", err)
	}
	setupMessageBytes, err := t.decodeDecryptMessage(encryptedEncodedSetupMsg, hexEncryptionKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode setup message: %w", err)
	}

	handle, err := mpcKeygenWrapper.KeyImporterNew(setupMessageBytes, localPartyID)
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

func (t *DKLSTssService) keygenWithRetry(sessionID string,
	hexEncryptionKey string,
	localPartyID string,
	isEdDSA bool,
	keygenCommittee []string) (string, string, error) {
	for i := 0; i < 3; i++ {
		publicKey, chainCode, err := t.keygen(sessionID, hexEncryptionKey, localPartyID, isEdDSA, keygenCommittee, i)
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

func (t *DKLSTssService) keygen(sessionID string,
	hexEncryptionKey string,
	localPartyID string,
	isEdDSA bool,
	keygenCommittee []string,
	attempt int) (string, string, error) {
	t.logger.WithFields(logrus.Fields{
		"session_id":       sessionID,
		"local_party_id":   localPartyID,
		"keygen_committee": keygenCommittee,
		"attempt":          attempt,
	}).Info("Keygen")
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

	handle, err := mpcKeygenWrapper.KeygenSessionFromSetup(setupMessageBytes, []byte(localPartyID))
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

func (t *DKLSTssService) processKeygenOutbound(handle Handle,
	sessionID string,
	hexEncryptionKey string,
	parties []string,
	localPartyID string,
	isEdDSA bool,
	wg *sync.WaitGroup) error {
	defer wg.Done()
	messenger := relay.NewMessenger(t.cfg.Relay.Server, sessionID, hexEncryptionKey, true, "")
	mpcKeygenWrapper := t.GetMPCKeygenWrapper(isEdDSA)
	var startTime *time.Time
	for {
		outbound, err := mpcKeygenWrapper.KeygenSessionOutputMessage(handle)
		if err != nil {
			t.logger.Error("failed to get output message", "error", err)
		}
		if len(outbound) == 0 {
			if t.isKeygenFinished.Load() {
				// even when the local party is finished , we better to wait for a little while to guarantee the outbound message is sent
				if startTime == nil {
					n := time.Now()
					startTime = &n
					continue
				}

				if time.Since(*startTime) < time.Second {
					continue
				}
				// we are finished
				return nil
			}
			time.Sleep(time.Millisecond * 100)
			continue
		}
		encodedOutbound := base64.StdEncoding.EncodeToString(outbound)
		for i := 0; i < len(parties); i++ {
			receiver, err := mpcKeygenWrapper.KeygenSessionMessageReceiver(handle, outbound, i)
			if err != nil {
				t.logger.Error("failed to get receiver message", "error", err)
			}
			if len(receiver) == 0 {
				continue
			}

			t.logger.Infoln("Sending message to", receiver)
			// send the message to the receiver
			if err := messenger.Send(localPartyID, receiver, encodedOutbound); err != nil {
				t.logger.Errorf("failed to send message: %v", err)
			}
		}
	}
}

func (t *DKLSTssService) processKeygenInbound(handle Handle,
	sessionID string,
	hexEncryptionKey string,
	isEdDSA bool,
	localPartyID string,
	wg *sync.WaitGroup) (string, string, error) {
	defer wg.Done()
	var messageCache sync.Map
	mpcKeygenWrapper := t.GetMPCKeygenWrapper(isEdDSA)
	relayClient := relay.NewRelayClient(t.cfg.Relay.Server)
	start := time.Now()
	for {
		select {
		case <-time.After(time.Millisecond * 100):
			if time.Since(start) > (time.Minute * 2) { // 2 minute timeout
				t.isKeygenFinished.Store(true)
				t.logger.Error("keygen timeout")
				return "", "", TssKeyGenTimeout
			}
			messages, err := relayClient.DownloadMessages(sessionID, localPartyID, "")
			if err != nil {
				t.logger.Error("failed to download messages", "error", err)
				continue
			}
			for _, message := range messages {
				if message.From == localPartyID {
					continue
				}
				cacheKey := fmt.Sprintf("%s-%s-%s", sessionID, localPartyID, message.Hash)
				if _, found := messageCache.Load(cacheKey); found {
					t.logger.Infof("Message already applied, skipping,hash: %s", message.Hash)
					continue
				}

				inboundBody, err := t.decodeDecryptMessage(message.Body, hexEncryptionKey)
				if err != nil {
					t.logger.Error("fail to decode inbound message", "error", err)
					continue
				}
				t.logger.Infoln("Received message from", message.From)
				isFinished, err := mpcKeygenWrapper.KeygenSessionInputMessage(handle, inboundBody)
				if err != nil {
					t.logger.Error("fail to apply input message", "error", err)
					continue
				}

				if err := relayClient.DeleteMessageFromServer(sessionID, localPartyID, message.Hash, ""); err != nil {
					t.logger.Error("fail to delete message", "error", err)
				}
				if isFinished {
					t.logger.Infoln("Keygen finished")
					result, err := mpcKeygenWrapper.KeygenSessionFinish(handle)
					if err != nil {
						t.logger.Error("fail to finish keygen", "error", err)
						return "", "", err
					}
					buf, err := mpcKeygenWrapper.KeyshareToBytes(result)
					if err != nil {
						t.logger.Error("fail to convert keyshare to bytes", "error", err)
						return "", "", err
					}
					encodedShare := base64.StdEncoding.EncodeToString(buf)
					publicKeyECDSABytes, err := mpcKeygenWrapper.KeysharePublicKey(result)
					if err != nil {
						t.logger.Error("fail to get public key", "error", err)
						return "", "", err
					}
					encodedPublicKey := hex.EncodeToString(publicKeyECDSABytes)
					t.logger.Infof("Public key: %s", encodedPublicKey)
					chainCode := ""
					if !isEdDSA {
						chainCodeBytes, err := mpcKeygenWrapper.KeyshareChainCode(result)
						if err != nil {
							t.logger.Error("fail to get chain code", "error", err)
							return "", "", err
						}
						chainCode = hex.EncodeToString(chainCodeBytes)
					}
					// This sleep give the local party a chance to send last message to others
					t.isKeygenFinished.Store(true)
					err = t.localStateAccessor.SaveLocalState(encodedPublicKey, encodedShare)
					return encodedPublicKey, chainCode, err
				}
			}
		}
	}
}

func (t *DKLSTssService) convertKeygenCommitteeToBytes(paries []string) ([]byte, error) {
	if len(paries) == 0 {
		return nil, fmt.Errorf("no parties provided")
	}
	result := make([]byte, 0)
	for _, party := range paries {
		result = append(result, []byte(party)...)
		result = append(result, byte(0))
	}
	// remove the last 0
	if len(result) > 0 {
		result = result[:len(result)-1]
	}
	return result, nil
}
