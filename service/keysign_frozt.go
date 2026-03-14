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

const maxSignAttempts = 3
const signRetryDelay = time.Second

func withSignRetry[T any](logger logrus.FieldLogger, label string, fn func() (T, error)) (T, error) {
	var result T
	var lastErr error
	for attempt := 1; attempt <= maxSignAttempts; attempt++ {
		result, lastErr = fn()
		if lastErr == nil {
			return result, nil
		}
		if attempt < maxSignAttempts {
			logger.WithFields(logrus.Fields{
				"attempt": attempt,
				"error":   lastErr,
			}).Warnf("%s attempt failed, retrying", label)
			time.Sleep(signRetryDelay)
		}
	}
	return result, lastErr
}

func (t *DKLSTssService) ProcessFroztKeysign(req types.KeysignRequest) (map[string]tss.KeysignResponse, error) {
	keyFolder := t.cfg.Server.VaultsFilePath
	localStateAccessor, err := relay.NewLocalStateAccessorImp(keyFolder, req.PublicKey, req.VaultPassword, t.blockStorage)
	if err != nil {
		return nil, fmt.Errorf("failed to create localStateAccessor: %w", err)
	}
	vault := localStateAccessor.Vault
	localPartyID := vault.LocalPartyId

	pubKeyHex := vault.PublicKeyFrozt
	keyshareB64, err := findKeyshareByPubkey(vault, pubKeyHex)
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
	defer func() {
		_ = relayClient.CompleteSession(req.SessionID, localPartyID)
	}()

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

	if req.ZcashSapling != nil && len(req.ZcashSapling.Alphas) > 0 {
		sighash := req.ZcashSapling.Sighash
		for i, alphaHex := range req.ZcashSapling.Alphas {
			sig, signErr := withSignRetry(t.logger, fmt.Sprintf("frozt sign[%d]", i), func() (*tss.KeysignResponse, error) {
				return t.froztSignWithAlpha(
					req.SessionID, req.HexEncryptionKey,
					keyPackage, pubKeyPackage,
					sighash, alphaHex, localPartyID, partiesJoined,
					i,
				)
			})
			if signErr != nil {
				return result, fmt.Errorf("frozt sign[%d] failed: %w", i, signErr)
			}

			key := fmt.Sprintf("%s:%d", sighash, i)
			result[key] = *sig
		}
	} else {
		for _, msg := range req.Messages {
			sig, signErr := withSignRetry(t.logger, "frozt sign", func() (*tss.KeysignResponse, error) {
				return t.froztSign(
					req.SessionID, req.HexEncryptionKey,
					keyPackage, pubKeyPackage,
					msg, localPartyID, partiesJoined,
				)
			})
			if signErr != nil {
				return result, fmt.Errorf("frozt sign failed: %w", signErr)
			}
			result[msg] = *sig
		}
	}

	return result, nil
}

func (t *DKLSTssService) froztSignWithAlpha(
	sessionID, hexEncryptionKey string,
	keyPackage, pubKeyPackage []byte,
	messageHex, alphaHex, localPartyID string,
	parties []string,
	index int,
) (*tss.KeysignResponse, error) {
	setupMsgID := fmt.Sprintf("frozt-sign-setup-%d", index)
	exchangeMsgID := fmt.Sprintf("frozt-sign-%d", index)

	relayClient := relay.NewRelayClient(t.cfg.Relay.Server)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	encryptedSetupMsg, err := relayClient.WaitForSetupMessage(ctx, sessionID, setupMsgID)
	if err != nil {
		return nil, fmt.Errorf("frozt sign[%d]: failed to get setup message: %w", index, err)
	}

	setup, err := t.decodeDecryptMessage(encryptedSetupMsg, hexEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("frozt sign[%d]: failed to decode setup message: %w", index, err)
	}

	t.logger.WithFields(logrus.Fields{
		"setupMsgID":    setupMsgID,
		"exchangeMsgID": exchangeMsgID,
		"index":         index,
		"setupLen":      len(setup),
	}).Info("Frozt sign: got setup from relay")

	partyIDs, setupParties, err := decodeFroztSetupPartyIDs(setup)
	if err != nil {
		return nil, fmt.Errorf("frozt sign[%d]: decode setup parties: %w", index, err)
	}
	if !samePartyOrder(parties, setupParties) {
		t.logger.WithFields(logrus.Fields{
			"relayParties": parties,
			"setupParties": setupParties,
			"index":        index,
		}).Warn("Frozt sign: relay party order differs from setup order; using setup order for identifiers")
	}

	alpha, err := hex.DecodeString(alphaHex)
	if err != nil {
		return nil, fmt.Errorf("frozt sign[%d]: decode alpha: %w", index, err)
	}

	session, err := frozt.SignSessionFromSetupWithAlpha(
		setup,
		[]byte(localPartyID),
		keyPackage,
		pubKeyPackage,
		alpha,
	)
	if err != nil {
		return nil, fmt.Errorf("frozt sign session[%d]: %w", index, err)
	}
	defer func() {
		if freeErr := frozt.SignSessionFree(session); freeErr != nil {
			t.logger.WithError(freeErr).Warnf("frozt sign[%d]: failed to free session", index)
		}
	}()

	finalSig, err := t.runFrostSignSession(
		session, sessionID, hexEncryptionKey, localPartyID, len(setupParties), partyIDs, exchangeMsgID,
		frozt.SignSessionTakeMsg, frozt.SignSessionFeed, frozt.SignSessionMsgReceiver, frozt.SignSessionResult,
	)
	if err != nil {
		return nil, err
	}

	t.logger.WithFields(logrus.Fields{
		"sig_len": len(finalSig),
		"index":   index,
	}).Info("Frozt signing complete (with alpha)")

	if len(finalSig) < 64 {
		return nil, fmt.Errorf("frozt sign[%d]: signature too short (%d bytes)", index, len(finalSig))
	}
	return &tss.KeysignResponse{
		Msg: messageHex,
		R:   hex.EncodeToString(finalSig[:32]),
		S:   hex.EncodeToString(finalSig[32:]),
	}, nil
}

func (t *DKLSTssService) froztSign(
	sessionID, hexEncryptionKey string,
	keyPackage, pubKeyPackage []byte,
	messageHex, localPartyID string,
	parties []string,
) (*tss.KeysignResponse, error) {
	setupMsgID := "frozt-sign-setup"
	exchangeMsgID := "frozt-sign"

	relayClient := relay.NewRelayClient(t.cfg.Relay.Server)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	encryptedSetupMsg, err := relayClient.WaitForSetupMessage(ctx, sessionID, setupMsgID)
	if err != nil {
		return nil, fmt.Errorf("frozt sign: failed to get setup message: %w", err)
	}

	setup, err := t.decodeDecryptMessage(encryptedSetupMsg, hexEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("frozt sign: failed to decode setup message: %w", err)
	}

	t.logger.WithFields(logrus.Fields{
		"setupMsgID":    setupMsgID,
		"exchangeMsgID": exchangeMsgID,
		"setupLen":      len(setup),
	}).Info("Frozt sign: got setup from relay")

	partyIDs, setupParties, err := decodeFroztSetupPartyIDs(setup)
	if err != nil {
		return nil, fmt.Errorf("frozt sign: decode setup parties: %w", err)
	}
	if !samePartyOrder(parties, setupParties) {
		t.logger.WithFields(logrus.Fields{
			"relayParties": parties,
			"setupParties": setupParties,
		}).Warn("Frozt sign: relay party order differs from setup order; using setup order for identifiers")
	}

	session, err := frozt.SignSessionFromSetup(setup, []byte(localPartyID), keyPackage, pubKeyPackage)
	if err != nil {
		return nil, fmt.Errorf("frozt sign session: %w", err)
	}
	defer func() {
		if freeErr := frozt.SignSessionFree(session); freeErr != nil {
			t.logger.WithError(freeErr).Warn("frozt sign: failed to free session")
		}
	}()

	finalSig, err := t.runFrostSignSession(
		session, sessionID, hexEncryptionKey, localPartyID, len(setupParties), partyIDs, exchangeMsgID,
		frozt.SignSessionTakeMsg, frozt.SignSessionFeed, frozt.SignSessionMsgReceiver, frozt.SignSessionResult,
	)
	if err != nil {
		return nil, err
	}

	t.logger.WithField("sig_len", len(finalSig)).Info("Frozt signing complete")

	if len(finalSig) < 64 {
		return nil, fmt.Errorf("frozt sign: signature too short (%d bytes)", len(finalSig))
	}
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

func samePartyOrder(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func decodeFroztSetupPartyIDs(setup []byte) (map[string]uint16, []string, error) {
	if len(setup) < 6 {
		return nil, nil, fmt.Errorf("setup too short")
	}

	pos := 0
	pos += 2 // max_signers
	pos += 2 // min_signers
	count := int(binary.LittleEndian.Uint16(setup[pos : pos+2]))
	pos += 2

	partyIDs := make(map[string]uint16, count)
	ordered := make([]string, 0, count)

	for i := 0; i < count; i++ {
		if pos+4 > len(setup) {
			return nil, nil, fmt.Errorf("setup truncated at party %d", i)
		}

		frostID := binary.LittleEndian.Uint16(setup[pos : pos+2])
		pos += 2

		nameLen := int(binary.LittleEndian.Uint16(setup[pos : pos+2]))
		pos += 2

		if pos+nameLen > len(setup) {
			return nil, nil, fmt.Errorf("setup party %d name truncated", i)
		}

		name := string(setup[pos : pos+nameLen])
		pos += nameLen

		partyIDs[name] = frostID
		ordered = append(ordered, name)
	}

	return partyIDs, ordered, nil
}

func (t *DKLSTssService) runFrostSignSession(
	session frozt.SessionHandle,
	sessionID, hexEncryptionKey, localPartyID string,
	partyCount int,
	partyIDs map[string]uint16,
	msgID string,
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
		sendErr := t.sendFrostSessionMsg(session, outbound, sessionID, hexEncryptionKey, localPartyID, partyCount, msgID, msgReceiver)
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
			senderID := partyIDs[msg.From]
			if senderID == 0 {
				t.logger.WithFields(logrus.Fields{
					"from":     msg.From,
					"partyIDs": partyIDs,
				}).Warn("frozt sign received message from unknown party in setup")
				_ = relayClient.DeleteMessageFromServer(sessionID, localPartyID, msg.Hash, msgID)
				continue
			}
			frame := make([]byte, 2+len(body))
			binary.LittleEndian.PutUint16(frame, senderID)
			copy(frame[2:], body)

			finished, procErr := feed(session, frame)
			_ = relayClient.DeleteMessageFromServer(sessionID, localPartyID, msg.Hash, msgID)
			progress = true
			if procErr != nil {
				t.logger.WithFields(logrus.Fields{
					"from":  msg.From,
					"error": procErr,
				}).Warn("frozt sign feed failed")
				continue
			}

			if finished {
				for {
					ob, obErr := takeMsg(session)
					if obErr != nil || len(ob) == 0 {
						break
					}
					_ = t.sendFrostSessionMsg(session, ob, sessionID, hexEncryptionKey, localPartyID, partyCount, msgID, msgReceiver)
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
			sendErr := t.sendFrostSessionMsg(session, outbound, sessionID, hexEncryptionKey, localPartyID, partyCount, msgID, msgReceiver)
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
	partyCount int,
	msgID string,
	msgReceiver signReceiverFunc,
) error {
	payload := msg[2:]
	messenger := relay.NewMessenger(t.cfg.Relay.Server, sessionID, hexEncryptionKey, true, msgID)
	encoded := base64.StdEncoding.EncodeToString(payload)
	for i := 0; i < partyCount; i++ {
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

func findKeyshareByPubkey(vault *vaultType.Vault, pubKey string) (string, error) {
	if pubKey == "" {
		return "", fmt.Errorf("public key is empty")
	}
	for _, ks := range vault.KeyShares {
		if ks.PublicKey == pubKey {
			return ks.Keyshare, nil
		}
	}
	return "", fmt.Errorf("keyshare for pubkey %s not found", pubKey)
}
