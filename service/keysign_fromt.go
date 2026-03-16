package service

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	fromt "github.com/vultisig/frost-zm/go/fromt"
	"github.com/vultisig/mobile-tss-lib/tss"

	"github.com/vultisig/vultiserver/internal/types"
	"github.com/vultisig/vultiserver/relay"
)

func (t *DKLSTssService) ProcessFromtKeysign(req types.KeysignRequest) (map[string]tss.KeysignResponse, error) {
	keyFolder := t.cfg.Server.VaultsFilePath
	localStateAccessor, err := relay.NewLocalStateAccessorImp(keyFolder, req.PublicKey, req.VaultPassword, t.blockStorage)
	if err != nil {
		return nil, fmt.Errorf("failed to create localStateAccessor: %w", err)
	}
	vault := localStateAccessor.Vault
	localPartyID := vault.LocalPartyId

	pubKeyHex := vault.PublicKeyFromt
	keyshareB64, err := findKeyshareByPubkey(vault, pubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("fromt keyshare: %w", err)
	}

	keyShare, err := base64.StdEncoding.DecodeString(keyshareB64)
	if err != nil {
		return nil, fmt.Errorf("fromt decode keyshare: %w", err)
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
	}).Info("Fromt keysign session started")

	if len(req.Messages) == 1 && req.Messages[0] == "key-image" {
		return withSignRetry(t.logger, "fromt key-image", func() (map[string]tss.KeysignResponse, error) {
			return t.keyImageFromt(req, keyShare, localPartyID, partiesJoined)
		})
	}

	if req.Chain == "Monero" && len(req.Messages) > 0 {
		return withSignRetry(t.logger, "fromt-sign", func() (map[string]tss.KeysignResponse, error) {
			return t.moneroSpendKeysign(req.Messages[0], req, keyShare, localPartyID, partiesJoined)
		})
	}

	result := map[string]tss.KeysignResponse{}
	for _, msg := range req.Messages {
		sig, signErr := withSignRetry(t.logger, "fromt sign", func() (*tss.KeysignResponse, error) {
			return t.fromtSign(
				req.SessionID, req.HexEncryptionKey,
				keyShare,
				msg, localPartyID, partiesJoined,
			)
		})
		if signErr != nil {
			return result, fmt.Errorf("fromt sign failed: %w", signErr)
		}
		result[msg] = *sig
	}

	return result, nil
}

func (t *DKLSTssService) fromtSign(
	sessionID, hexEncryptionKey string,
	keyShare []byte,
	messageHex, localPartyID string,
	parties []string,
) (*tss.KeysignResponse, error) {
	msgPrefix := messageHex
	if len(msgPrefix) > 8 {
		msgPrefix = msgPrefix[:8]
	}
	msgID := "fromt-sign-" + msgPrefix

	relayClient := relay.NewRelayClient(t.cfg.Relay.Server)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	encryptedSetupMsg, err := relayClient.WaitForSetupMessage(ctx, sessionID, msgID)
	if err != nil {
		return nil, fmt.Errorf("fromt sign: failed to get setup message: %w", err)
	}

	setup, err := t.decodeDecryptMessage(encryptedSetupMsg, hexEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("fromt sign: failed to decode setup message: %w", err)
	}

	t.logger.WithFields(logrus.Fields{
		"msgID":    msgID,
		"setupLen": len(setup),
	}).Info("Fromt sign: got setup from relay")

	keyPackage, pubKeyPackage, err := extractFromtBundleParts(keyShare)
	if err != nil {
		return nil, fmt.Errorf("fromt extract bundle parts: %w", err)
	}

	session, err := fromt.SignSessionFromSetup(setup, []byte(localPartyID), keyPackage, pubKeyPackage)
	if err != nil {
		return nil, fmt.Errorf("fromt sign session: %w", err)
	}
	defer func() {
		if freeErr := fromt.SignSessionFree(session); freeErr != nil {
			t.logger.WithError(freeErr).Warn("fromt sign: failed to free session")
		}
	}()
	deadline := time.Now().Add(time.Minute)

	for {
		outbound, takeErr := fromt.SignSessionTakeMsg(session)
		if takeErr != nil {
			return nil, fmt.Errorf("fromt sign take msg: %w", takeErr)
		}
		if len(outbound) == 0 {
			break
		}
		t.sendFromtSessionMsg(session, outbound, sessionID, hexEncryptionKey, localPartyID, parties, msgID)
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

			finished, procErr := fromt.SignSessionFeed(session, frame)
			_ = relayClient.DeleteMessageFromServer(sessionID, localPartyID, msg.Hash, msgID)
			progress = true
			if procErr != nil {
				t.logger.WithFields(logrus.Fields{
					"from":  msg.From,
					"error": procErr,
				}).Warn("fromt sign feed failed")
				continue
			}

			if finished {
				for {
					ob, obErr := fromt.SignSessionTakeMsg(session)
					if obErr != nil || len(ob) == 0 {
						break
					}
					t.sendFromtSessionMsg(session, ob, sessionID, hexEncryptionKey, localPartyID, parties, msgID)
				}
				finalSig, resErr := fromt.SignSessionResult(session)
				if resErr != nil {
					return nil, fmt.Errorf("fromt sign result: %w", resErr)
				}
				t.logger.WithField("sig_len", len(finalSig)).Info("Fromt signing complete")
				if len(finalSig) < 64 {
					return nil, fmt.Errorf("fromt sign: signature too short (%d bytes)", len(finalSig))
				}
				return &tss.KeysignResponse{
					Msg: messageHex,
					R:   hex.EncodeToString(finalSig[:32]),
					S:   hex.EncodeToString(finalSig[32:]),
				}, nil
			}
		}

		for {
			outbound, takeErr := fromt.SignSessionTakeMsg(session)
			if takeErr != nil {
				return nil, fmt.Errorf("fromt sign take msg: %w", takeErr)
			}
			if len(outbound) == 0 {
				break
			}
			t.sendFromtSessionMsg(session, outbound, sessionID, hexEncryptionKey, localPartyID, parties, msgID)
			progress = true
		}

		if !progress {
			time.Sleep(100 * time.Millisecond)
		}
	}
	return nil, fmt.Errorf("fromt sign timeout")
}

func (t *DKLSTssService) sendFromtSessionMsg(
	session *fromt.SessionHandle,
	msg []byte,
	sessionID, hexEncryptionKey, localPartyID string,
	parties []string, msgID string,
) {
	payload := msg[2:]
	messenger := relay.NewMessenger(t.cfg.Relay.Server, sessionID, hexEncryptionKey, true, msgID)
	encoded := base64.StdEncoding.EncodeToString(payload)
	for i := range parties {
		receiver, err := fromt.SignSessionMsgReceiver(session, msg, i)
		if err != nil {
			continue
		}
		if len(receiver) == 0 {
			continue
		}
		_ = messenger.Send(localPartyID, string(receiver), encoded)
	}
}

func extractFromtBundleParts(bundle []byte) (keyPackage, pubKeyPackage []byte, err error) {
	pos := 0
	if len(bundle) < 1+1+32+4 {
		return nil, nil, fmt.Errorf("fromt bundle too short")
	}

	version := bundle[pos]
	pos++
	if version != 1 && version != 2 {
		return nil, nil, fmt.Errorf("fromt bundle unknown version %d", version)
	}

	pos++     // network
	pos += 32 // view_key

	if version >= 2 {
		if pos+8 > len(bundle) {
			return nil, nil, fmt.Errorf("fromt bundle truncated at birthday")
		}
		pos += 8 // birthday
	}

	if pos+4 > len(bundle) {
		return nil, nil, fmt.Errorf("fromt bundle truncated at kp_len")
	}
	kpLen := int(binary.LittleEndian.Uint32(bundle[pos : pos+4]))
	pos += 4
	if pos+kpLen > len(bundle) {
		return nil, nil, fmt.Errorf("fromt bundle truncated at key_package")
	}
	keyPackage = bundle[pos : pos+kpLen]
	pos += kpLen

	if pos+4 > len(bundle) {
		return nil, nil, fmt.Errorf("fromt bundle truncated at pkp_len")
	}
	pkpLen := int(binary.LittleEndian.Uint32(bundle[pos : pos+4]))
	pos += 4
	if pos+pkpLen > len(bundle) {
		return nil, nil, fmt.Errorf("fromt bundle truncated at pub_key_package")
	}
	pubKeyPackage = bundle[pos : pos+pkpLen]

	return keyPackage, pubKeyPackage, nil
}

func (t *DKLSTssService) moneroSpendKeysign(
	signableTxHex string,
	req types.KeysignRequest,
	keyShare []byte,
	localPartyID string,
	parties []string,
) (map[string]tss.KeysignResponse, error) {
	signableTx, err := hex.DecodeString(signableTxHex)
	if err != nil {
		return nil, fmt.Errorf("decode signable_tx hex: %w", err)
	}

	rawTx, err := t.moneroSpendSign(
		req.SessionID, req.HexEncryptionKey,
		keyShare, signableTx,
		localPartyID, parties,
	)
	if err != nil {
		return nil, fmt.Errorf("monero spend sign: %w", err)
	}

	txHex := hex.EncodeToString(rawTx)
	result := map[string]tss.KeysignResponse{
		"monero-spend": {
			Msg: txHex,
			R:   txHex,
			S:   "",
		},
	}
	return result, nil
}

func (t *DKLSTssService) moneroSpendSign(
	sessionID, hexEncryptionKey string,
	keyShare, signableTx []byte,
	localPartyID string,
	parties []string,
) ([]byte, error) {
	relayClient := relay.NewRelayClient(t.cfg.Relay.Server)
	localFrostID := getFrostIdStatic(localPartyID, parties)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if len(signableTx) == 0 {
		encryptedSetupMsg, err := relayClient.WaitForSetupMessage(ctx, sessionID, "monero-spend-setup")
		if err != nil {
			return nil, fmt.Errorf("monero spend: wait for setup: %w", err)
		}

		setup, err := t.decodeDecryptMessage(encryptedSetupMsg, hexEncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("monero spend: decode setup: %w", err)
		}
		signableTx = setup
	}

	t.logger.WithField("signable_tx_len", len(signableTx)).Info("Monero spend: got signableTx from relay")

	handle, preprocess, err := fromt.SpendPreprocess(keyShare, signableTx)
	if err != nil {
		return nil, fmt.Errorf("spend preprocess: %w", err)
	}
	defer func() {
		if closeErr := handle.Close(); closeErr != nil {
			t.logger.WithError(closeErr).Warn("monero spend: failed to close preprocess handle")
		}
	}()

	preprocessMap, err := t.spendExchangeRound(
		ctx, relayClient,
		sessionID, hexEncryptionKey,
		localPartyID, localFrostID, parties,
		"monero-spend-preprocess", preprocess,
		true,
	)
	if err != nil {
		return nil, fmt.Errorf("spend preprocess exchange: %w", err)
	}

	sigHandle, share, err := fromt.SpendSign(handle, preprocessMap)
	if err != nil {
		return nil, fmt.Errorf("spend sign: %w", err)
	}
	defer func() {
		if closeErr := sigHandle.Close(); closeErr != nil {
			t.logger.WithError(closeErr).Warn("monero spend: failed to close signature handle")
		}
	}()

	sharesMap, err := t.spendExchangeRound(
		ctx, relayClient,
		sessionID, hexEncryptionKey,
		localPartyID, localFrostID, parties,
		"monero-spend-share", share,
		false,
	)
	if err != nil {
		return nil, fmt.Errorf("spend share exchange: %w", err)
	}

	rawTx, err := fromt.SpendComplete(sigHandle, sharesMap)
	if err != nil {
		return nil, fmt.Errorf("spend complete: %w", err)
	}

	t.logger.WithField("raw_tx_len", len(rawTx)).Info("Monero spend: signing complete")
	return rawTx, nil
}

func (t *DKLSTssService) keyImageFromt(
	req types.KeysignRequest,
	keyShare []byte,
	localPartyID string,
	parties []string,
) (map[string]tss.KeysignResponse, error) {
	setupMsgID := "fromt-keyimage-setup"
	exchangeMsgID := "fromt-keyimage"

	relayClient := relay.NewRelayClient(t.cfg.Relay.Server)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	encryptedSetupMsg, err := relayClient.WaitForSetupMessage(ctx, req.SessionID, setupMsgID)
	if err != nil {
		return nil, fmt.Errorf("fromt key image: failed to get setup message: %w", err)
	}

	setup, err := t.decodeDecryptMessage(encryptedSetupMsg, req.HexEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("fromt key image: failed to decode setup message: %w", err)
	}

	t.logger.WithFields(logrus.Fields{
		"setupMsgID": setupMsgID,
		"setupLen":   len(setup),
	}).Info("Fromt key image: got setup from relay")

	session, err := fromt.KeyImageSessionFromSetup(setup, []byte(localPartyID), keyShare)
	if err != nil {
		return nil, fmt.Errorf("fromt key image session: %w", err)
	}
	defer func() {
		if freeErr := fromt.KeyImageSessionFree(session); freeErr != nil {
			t.logger.WithError(freeErr).Warn("fromt key image: failed to free session")
		}
	}()

	deadline := time.Now().Add(time.Minute)

	for {
		outbound, takeErr := fromt.KeyImageSessionTakeMsg(session)
		if takeErr != nil {
			return nil, fmt.Errorf("fromt key image take msg: %w", takeErr)
		}
		if len(outbound) == 0 {
			break
		}
		t.sendKeyImageSessionMsg(session, outbound, req.SessionID, req.HexEncryptionKey, localPartyID, parties, exchangeMsgID)
	}

	for time.Now().Before(deadline) {
		messages, dlErr := relayClient.DownloadMessages(req.SessionID, localPartyID, exchangeMsgID)
		if dlErr != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		progress := false
		for _, msg := range messages {
			if msg.From == localPartyID {
				continue
			}
			body, decErr := t.decodeDecryptMessage(msg.Body, req.HexEncryptionKey)
			if decErr != nil {
				_ = relayClient.DeleteMessageFromServer(req.SessionID, localPartyID, msg.Hash, exchangeMsgID)
				continue
			}
			senderID := getFrostIdStatic(msg.From, parties)
			frame := make([]byte, 2+len(body))
			binary.LittleEndian.PutUint16(frame, senderID)
			copy(frame[2:], body)

			finished, procErr := fromt.KeyImageSessionFeed(session, frame)
			_ = relayClient.DeleteMessageFromServer(req.SessionID, localPartyID, msg.Hash, exchangeMsgID)
			progress = true
			if procErr != nil {
				t.logger.WithFields(logrus.Fields{
					"from":  msg.From,
					"error": procErr,
				}).Warn("fromt key image feed failed")
				continue
			}

			if finished {
				for {
					ob, obErr := fromt.KeyImageSessionTakeMsg(session)
					if obErr != nil || len(ob) == 0 {
						break
					}
					t.sendKeyImageSessionMsg(session, ob, req.SessionID, req.HexEncryptionKey, localPartyID, parties, exchangeMsgID)
				}
				keyImages, resErr := fromt.KeyImageSessionResult(session)
				if resErr != nil {
					return nil, fmt.Errorf("fromt key image result: %w", resErr)
				}
				t.logger.WithField("result_len", len(keyImages)).Info("Fromt key image complete")
				return map[string]tss.KeysignResponse{
					"key-image": {
						Msg: hex.EncodeToString(keyImages),
						R:   hex.EncodeToString(keyImages),
						S:   "",
					},
				}, nil
			}
		}

		for {
			outbound, takeErr := fromt.KeyImageSessionTakeMsg(session)
			if takeErr != nil {
				return nil, fmt.Errorf("fromt key image take msg: %w", takeErr)
			}
			if len(outbound) == 0 {
				break
			}
			t.sendKeyImageSessionMsg(session, outbound, req.SessionID, req.HexEncryptionKey, localPartyID, parties, exchangeMsgID)
			progress = true
		}

		if !progress {
			time.Sleep(100 * time.Millisecond)
		}
	}
	return nil, fmt.Errorf("fromt key image timeout")
}

func (t *DKLSTssService) sendKeyImageSessionMsg(
	session *fromt.SessionHandle,
	msg []byte,
	sessionID, hexEncryptionKey, localPartyID string,
	parties []string, msgID string,
) {
	payload := msg[2:]
	messenger := relay.NewMessenger(t.cfg.Relay.Server, sessionID, hexEncryptionKey, true, msgID)
	encoded := base64.StdEncoding.EncodeToString(payload)
	for i := range parties {
		receiver, err := fromt.KeyImageSessionMsgReceiver(session, msg, i)
		if err != nil {
			continue
		}
		if len(receiver) == 0 {
			continue
		}
		_ = messenger.Send(localPartyID, string(receiver), encoded)
	}
}

func (t *DKLSTssService) spendExchangeRound(
	ctx context.Context,
	relayClient *relay.Client,
	sessionID, hexEncryptionKey string,
	localPartyID string, localFrostID uint16,
	parties []string,
	messageID string,
	localData []byte,
	includeSelf bool,
) ([]byte, error) {
	messenger := relay.NewMessenger(t.cfg.Relay.Server, sessionID, hexEncryptionKey, true, messageID)
	encoded := base64.StdEncoding.EncodeToString(localData)

	for _, party := range parties {
		if party == localPartyID {
			continue
		}
		sendErr := messenger.Send(localPartyID, party, encoded)
		if sendErr != nil {
			t.logger.WithField("error", sendErr).Warn("monero spend: failed to send round message")
		}
	}

	localIDBytes, err := fromt.EncodeIdentifier(localFrostID)
	if err != nil {
		return nil, fmt.Errorf("encode local identifier: %w", err)
	}

	var entries []fromt.MapEntry
	expected := len(parties) - 1
	if includeSelf {
		entries = []fromt.MapEntry{
			{ID: localIDBytes, Value: localData},
		}
		expected = len(parties)
	}

	for len(entries) < expected {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		messages, dlErr := relayClient.DownloadMessages(sessionID, localPartyID, messageID)
		if dlErr != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		for _, msg := range messages {
			if msg.From == localPartyID {
				continue
			}
			body, decErr := t.decodeDecryptMessage(msg.Body, hexEncryptionKey)
			if decErr != nil {
				_ = relayClient.DeleteMessageFromServer(sessionID, localPartyID, msg.Hash, messageID)
				continue
			}

			senderFrostID := getFrostIdStatic(msg.From, parties)
			senderIDBytes, idErr := fromt.EncodeIdentifier(senderFrostID)
			if idErr != nil {
				continue
			}

			entries = append(entries, fromt.MapEntry{
				ID:    senderIDBytes,
				Value: body,
			})
			_ = relayClient.DeleteMessageFromServer(sessionID, localPartyID, msg.Hash, messageID)
		}

		if len(entries) < expected {
			time.Sleep(100 * time.Millisecond)
		}
	}

	return fromt.EncodeMap(entries), nil
}
