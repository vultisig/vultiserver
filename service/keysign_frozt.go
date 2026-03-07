package service

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	frozt "github.com/vultisig/frost-zm/go/frozt"
	"github.com/vultisig/mobile-tss-lib/tss"

	vaultType "github.com/vultisig/commondata/go/vultisig/vault/v1"

	"github.com/vultisig/vultiserver/internal/types"
	"github.com/vultisig/vultiserver/relay"
)

func (t *DKLSTssService) ProcessFroztKeysign(req types.KeysignRequest) (map[string]tss.KeysignResponse, error) {
	keyFolder := t.cfg.Server.VaultsFilePath
	localStateAccessor, err := relay.NewLocalStateAccessorImp(keyFolder, req.PublicKey, req.VaultPassword, t.blockStorage)
	if err != nil {
		return nil, fmt.Errorf("failed to create localStateAccessor: %w", err)
	}
	t.localStateAccessor = localStateAccessor
	vault := localStateAccessor.Vault
	localPartyID := vault.LocalPartyId

	keyshareB64, pubKeyHex, err := findChainKeyshare(vault, "ZcashSapling")
	if err != nil {
		return nil, fmt.Errorf("frozt keyshare: %w", err)
	}

	bundleBytes, err := base64.StdEncoding.DecodeString(keyshareB64)
	if err != nil {
		return nil, fmt.Errorf("frozt decode bundle: %w", err)
	}

	keyPackage, err := frozt.KeyShareBundleKeyPackage(bundleBytes)
	if err != nil {
		return nil, fmt.Errorf("frozt unpack keyPackage: %w", err)
	}

	pubKeyPackage, err := frozt.KeyShareBundlePubKeyPackage(bundleBytes)
	if err != nil {
		return nil, fmt.Errorf("frozt unpack pubKeyPackage: %w", err)
	}

	relayClient := relay.NewRelayClient(t.cfg.Relay.Server)
	err = relayClient.RegisterSessionWithRetry(req.SessionID, localPartyID)
	if err != nil {
		return nil, fmt.Errorf("failed to register session: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	partiesJoined, err := relayClient.WaitForSessionStart(ctx, req.SessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to wait for session start: %w", err)
	}

	t.logger.WithFields(logrus.Fields{
		"session":   req.SessionID,
		"parties":   partiesJoined,
		"publicKey": pubKeyHex,
	}).Info("Frozt keysign session started")

	result := map[string]tss.KeysignResponse{}
	for _, msg := range req.Messages {
		sig, signErr := t.froztSign(
			req.SessionID, req.HexEncryptionKey,
			keyPackage, pubKeyPackage,
			msg, localPartyID, partiesJoined,
		)
		if signErr != nil {
			return result, fmt.Errorf("frozt sign failed: %w", signErr)
		}
		result[msg] = *sig
	}

	completeErr := relayClient.CompleteSession(req.SessionID, localPartyID)
	if completeErr != nil {
		t.logger.WithField("error", completeErr).Error("Failed to complete session")
	}

	return result, nil
}

func (t *DKLSTssService) froztSign(
	sessionID, hexEncryptionKey string,
	keyPackage, pubKeyPackage []byte,
	messageHex, localPartyID string,
	parties []string,
) (*tss.KeysignResponse, error) {
	msgBytes, err := hex.DecodeString(messageHex)
	if err != nil {
		return nil, fmt.Errorf("decode message hex: %w", err)
	}

	partyInfos := buildFroztPartyInfos(parties)
	setup, err := frozt.SignSetupMsgNew(msgBytes, partyInfos)
	if err != nil {
		return nil, fmt.Errorf("frozt sign setup: %w", err)
	}

	session, err := frozt.SignSessionFromSetup(setup, []byte(localPartyID), keyPackage, pubKeyPackage)
	if err != nil {
		return nil, fmt.Errorf("frozt sign session: %w", err)
	}
	defer frozt.SignSessionFree(session)

	msgID := "frozt-sign-" + messageHex[:8]

	finalSig, err := t.runFrostSignSession(
		session, sessionID, hexEncryptionKey, localPartyID, parties, msgID,
		frozt.SignSessionTakeMsg, frozt.SignSessionFeed, frozt.SignSessionMsgReceiver, frozt.SignSessionResult,
	)
	if err != nil {
		return nil, err
	}

	t.logger.WithField("sig_len", len(finalSig)).Info("Frozt signing complete")

	return &tss.KeysignResponse{
		Msg: messageHex,
		R:   hex.EncodeToString(finalSig[:32]),
		S:   hex.EncodeToString(finalSig[32:]),
	}, nil
}

type signTakeFunc func(frozt.SessionHandle) ([]byte, error)
type signFeedFunc func(frozt.SessionHandle, []byte) (bool, error)
type signReceiverFunc func(frozt.SessionHandle, []byte, int) ([]byte, error)
type signResultFunc func(frozt.SessionHandle) ([]byte, error)

func (t *DKLSTssService) runFrostSignSession(
	session frozt.SessionHandle,
	sessionID, hexEncryptionKey, localPartyID string,
	parties []string, msgID string,
	takeMsg signTakeFunc,
	feed signFeedFunc,
	msgReceiver signReceiverFunc,
	result signResultFunc,
) ([]byte, error) {
	relayClient := relay.NewRelayClient(t.cfg.Relay.Server)
	deadline := time.Now().Add(time.Minute)

	for {
		outbound, err := takeMsg(session)
		if err != nil {
			return nil, fmt.Errorf("frozt sign take msg: %w", err)
		}
		if len(outbound) == 0 {
			break
		}
		sendErr := t.sendFrostSessionMsg(session, outbound, sessionID, hexEncryptionKey, localPartyID, parties, msgID, msgReceiver)
		if sendErr != nil {
			return nil, sendErr
		}
	}

	for time.Now().Before(deadline) {
		messages, dlErr := relayClient.DownloadMessages(sessionID, localPartyID, msgID)
		if dlErr != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		progress := false
		for _, msg := range messages {
			if msg.From == localPartyID {
				continue
			}
			body, decErr := t.decodeDecryptMessage(msg.Body, hexEncryptionKey)
			if decErr != nil {
				_ = relayClient.DeleteMessageFromServer(sessionID, localPartyID, msg.Hash, msgID)
				continue
			}
			senderID := getFrostIdStatic(msg.From, parties)
			frame := make([]byte, 2+len(body))
			binary.LittleEndian.PutUint16(frame, senderID)
			copy(frame[2:], body)

			finished, procErr := feed(session, frame)
			if procErr != nil {
				t.logger.WithFields(logrus.Fields{
					"from":  msg.From,
					"error": procErr,
				}).Warn("frozt sign feed failed")
			}
			_ = relayClient.DeleteMessageFromServer(sessionID, localPartyID, msg.Hash, msgID)
			progress = true

			if finished {
				for {
					ob, obErr := takeMsg(session)
					if obErr != nil || len(ob) == 0 {
						break
					}
					_ = t.sendFrostSessionMsg(session, ob, sessionID, hexEncryptionKey, localPartyID, parties, msgID, msgReceiver)
				}
				return result(session)
			}
		}

		for {
			outbound, err := takeMsg(session)
			if err != nil {
				return nil, fmt.Errorf("frozt sign take msg: %w", err)
			}
			if len(outbound) == 0 {
				break
			}
			sendErr := t.sendFrostSessionMsg(session, outbound, sessionID, hexEncryptionKey, localPartyID, parties, msgID, msgReceiver)
			if sendErr != nil {
				return nil, sendErr
			}
			progress = true
		}

		if !progress {
			time.Sleep(100 * time.Millisecond)
		}
	}
	return nil, fmt.Errorf("frozt sign timeout")
}

func (t *DKLSTssService) sendFrostSessionMsg(
	session frozt.SessionHandle,
	msg []byte,
	sessionID, hexEncryptionKey, localPartyID string,
	parties []string, msgID string,
	msgReceiver signReceiverFunc,
) error {
	payload := msg[2:]
	messenger := relay.NewMessenger(t.cfg.Relay.Server, sessionID, hexEncryptionKey, true, msgID)
	encoded := base64.StdEncoding.EncodeToString(payload)
	for i := range parties {
		receiver, err := msgReceiver(session, msg, i)
		if err != nil {
			return fmt.Errorf("frozt sign msg receiver: %w", err)
		}
		if len(receiver) == 0 {
			continue
		}
		_ = messenger.Send(localPartyID, string(receiver), encoded)
	}
	return nil
}

func findChainKeyshare(vault *vaultType.Vault, chain string) (string, string, error) {
	pubKey := ""
	for _, cpk := range vault.ChainPublicKeys {
		if cpk.Chain == chain {
			pubKey = cpk.PublicKey
			break
		}
	}
	if pubKey == "" {
		return "", "", fmt.Errorf("chain %s not found in vault", chain)
	}

	for _, ks := range vault.KeyShares {
		if ks.PublicKey == pubKey {
			return ks.Keyshare, pubKey, nil
		}
	}
	return "", "", fmt.Errorf("keyshare for chain %s (pubkey %s) not found", chain, pubKey)
}
