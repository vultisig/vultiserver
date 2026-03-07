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
	t.localStateAccessor = localStateAccessor
	vault := localStateAccessor.Vault
	localPartyID := vault.LocalPartyId

	keyshareB64, pubKeyHex, err := findChainKeyshare(vault, "Monero")
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

	result := map[string]tss.KeysignResponse{}
	for _, msg := range req.Messages {
		sig, signErr := t.fromtSign(
			req.SessionID, req.HexEncryptionKey,
			keyShare,
			msg, localPartyID, partiesJoined,
		)
		if signErr != nil {
			return result, fmt.Errorf("fromt sign failed: %w", signErr)
		}
		result[msg] = *sig
	}

	completeErr := relayClient.CompleteSession(req.SessionID, localPartyID)
	if completeErr != nil {
		t.logger.WithField("error", completeErr).Error("Failed to complete session")
	}

	return result, nil
}

func (t *DKLSTssService) fromtSign(
	sessionID, hexEncryptionKey string,
	keyShare []byte,
	messageHex, localPartyID string,
	parties []string,
) (*tss.KeysignResponse, error) {
	msgBytes, err := hex.DecodeString(messageHex)
	if err != nil {
		return nil, fmt.Errorf("decode message hex: %w", err)
	}

	partyInfos := buildFromtPartyInfos(parties)
	setup, err := fromt.SignSetupMsgNew(msgBytes, partyInfos)
	if err != nil {
		return nil, fmt.Errorf("fromt sign setup: %w", err)
	}

	keyPackage, pubKeyPackage, err := extractFromtBundleParts(keyShare)
	if err != nil {
		return nil, fmt.Errorf("fromt extract bundle parts: %w", err)
	}

	session, err := fromt.SignSessionFromSetup(setup, []byte(localPartyID), keyPackage, pubKeyPackage)
	if err != nil {
		return nil, fmt.Errorf("fromt sign session: %w", err)
	}
	defer fromt.SignSessionFree(session)

	msgID := "fromt-sign-" + messageHex[:8]
	relayClient := relay.NewRelayClient(t.cfg.Relay.Server)
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
			if procErr != nil {
				t.logger.WithFields(logrus.Fields{
					"from":  msg.From,
					"error": procErr,
				}).Warn("fromt sign feed failed")
			}
			_ = relayClient.DeleteMessageFromServer(sessionID, localPartyID, msg.Hash, msgID)
			progress = true

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

	pos++ // network
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
