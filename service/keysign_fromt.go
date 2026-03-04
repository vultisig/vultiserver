package service

import (
	"context"
	"encoding/base64"
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

	myFrostID := getFrostIdStatic(localPartyID, parties)
	if myFrostID == 0 {
		return nil, fmt.Errorf("local party %s not found in parties", localPartyID)
	}

	nonces, commitment, err := fromt.SignCommit(keyShare)
	if err != nil {
		return nil, fmt.Errorf("fromt SignCommit: %w", err)
	}
	defer nonces.Close()

	commitMsgID := "fromt-sign-commit-" + messageHex[:8]
	shareMsgID := "fromt-sign-share-" + messageHex[:8]

	messenger := relay.NewMessenger(t.cfg.Relay.Server, sessionID, hexEncryptionKey, true, commitMsgID)
	encodedCommitment := base64.StdEncoding.EncodeToString(commitment)
	for _, peer := range parties {
		if peer == localPartyID {
			continue
		}
		sendErr := messenger.Send(localPartyID, peer, encodedCommitment)
		if sendErr != nil {
			t.logger.WithField("error", sendErr).Error("failed to send fromt commitment")
		}
	}

	peerCommitments, err := t.waitForFrostMessages(sessionID, hexEncryptionKey, localPartyID, commitMsgID, len(parties)-1)
	if err != nil {
		return nil, fmt.Errorf("fromt commitments: %w", err)
	}

	allCommitments := make(map[string][]byte)
	allCommitments[localPartyID] = commitment
	for k, v := range peerCommitments {
		allCommitments[k] = v
	}

	commitmentsMap := buildFromtMap(allCommitments, parties)

	signingPackage, err := fromt.SignCreatePackage(msgBytes, commitmentsMap)
	if err != nil {
		return nil, fmt.Errorf("fromt SignCreatePackage: %w", err)
	}

	signatureShare, err := fromt.Sign(signingPackage, nonces, keyShare)
	if err != nil {
		return nil, fmt.Errorf("fromt Sign: %w", err)
	}

	shareMessenger := relay.NewMessenger(t.cfg.Relay.Server, sessionID, hexEncryptionKey, true, shareMsgID)
	encodedShare := base64.StdEncoding.EncodeToString(signatureShare)
	for _, peer := range parties {
		if peer == localPartyID {
			continue
		}
		sendErr := shareMessenger.Send(localPartyID, peer, encodedShare)
		if sendErr != nil {
			t.logger.WithField("error", sendErr).Error("failed to send fromt share")
		}
	}

	peerShares, err := t.waitForFrostMessages(sessionID, hexEncryptionKey, localPartyID, shareMsgID, len(parties)-1)
	if err != nil {
		return nil, fmt.Errorf("fromt shares: %w", err)
	}

	allShares := make(map[string][]byte)
	allShares[localPartyID] = signatureShare
	for k, v := range peerShares {
		allShares[k] = v
	}

	sharesMap := buildFromtMap(allShares, parties)

	finalSig, err := fromt.SignAggregate(signingPackage, sharesMap, keyShare)
	if err != nil {
		return nil, fmt.Errorf("fromt SignAggregate: %w", err)
	}

	t.logger.WithField("sig_len", len(finalSig)).Info("Fromt signing complete")

	resp := &tss.KeysignResponse{
		Msg: messageHex,
		R:   hex.EncodeToString(finalSig[:32]),
		S:   hex.EncodeToString(finalSig[32:]),
	}
	return resp, nil
}
