package service

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
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

	myFrostID := getFrostIdStatic(localPartyID, parties)
	if myFrostID == 0 {
		return nil, fmt.Errorf("local party %s not found in parties", localPartyID)
	}

	nonces, commitment, err := frozt.SignCommit(keyPackage)
	if err != nil {
		return nil, fmt.Errorf("frozt SignCommit: %w", err)
	}
	defer nonces.Close()

	commitMsgID := "frozt-sign-commit-" + messageHex[:8]
	shareMsgID := "frozt-sign-share-" + messageHex[:8]

	messenger := relay.NewMessenger(t.cfg.Relay.Server, sessionID, hexEncryptionKey, true, commitMsgID)
	encodedCommitment := base64.StdEncoding.EncodeToString(commitment)
	for _, peer := range parties {
		if peer == localPartyID {
			continue
		}
		sendErr := messenger.Send(localPartyID, peer, encodedCommitment)
		if sendErr != nil {
			t.logger.WithField("error", sendErr).Error("failed to send frozt commitment")
		}
	}

	peerCommitments, err := t.waitForFrostMessages(sessionID, hexEncryptionKey, localPartyID, commitMsgID, len(parties)-1)
	if err != nil {
		return nil, fmt.Errorf("frozt commitments: %w", err)
	}

	allCommitments := make(map[string][]byte)
	allCommitments[localPartyID] = commitment
	for k, v := range peerCommitments {
		allCommitments[k] = v
	}

	commitmentsMap := buildFrostMapStatic(allCommitments, parties)

	signingPackage, randomizer, err := frozt.SignNewPackage(msgBytes, commitmentsMap, pubKeyPackage)
	if err != nil {
		return nil, fmt.Errorf("frozt SignNewPackage: %w", err)
	}

	signatureShare, err := frozt.Sign(signingPackage, nonces, keyPackage, randomizer)
	if err != nil {
		return nil, fmt.Errorf("frozt Sign: %w", err)
	}

	shareMessenger := relay.NewMessenger(t.cfg.Relay.Server, sessionID, hexEncryptionKey, true, shareMsgID)
	encodedShare := base64.StdEncoding.EncodeToString(signatureShare)
	for _, peer := range parties {
		if peer == localPartyID {
			continue
		}
		sendErr := shareMessenger.Send(localPartyID, peer, encodedShare)
		if sendErr != nil {
			t.logger.WithField("error", sendErr).Error("failed to send frozt share")
		}
	}

	peerShares, err := t.waitForFrostMessages(sessionID, hexEncryptionKey, localPartyID, shareMsgID, len(parties)-1)
	if err != nil {
		return nil, fmt.Errorf("frozt shares: %w", err)
	}

	allShares := make(map[string][]byte)
	allShares[localPartyID] = signatureShare
	for k, v := range peerShares {
		allShares[k] = v
	}

	sharesMap := buildFrostMapStatic(allShares, parties)

	finalSig, err := frozt.SignAggregate(signingPackage, sharesMap, pubKeyPackage, randomizer)
	if err != nil {
		return nil, fmt.Errorf("frozt SignAggregate: %w", err)
	}

	t.logger.WithField("sig_len", len(finalSig)).Info("Frozt signing complete")

	resp := &tss.KeysignResponse{
		Msg: messageHex,
		R:   hex.EncodeToString(finalSig[:32]),
		S:   hex.EncodeToString(finalSig[32:]),
	}
	return resp, nil
}

func (t *DKLSTssService) waitForFrostMessages(
	sessionID, hexEncryptionKey, localPartyID, msgID string,
	expected int,
) (map[string][]byte, error) {
	relayClient := relay.NewRelayClient(t.cfg.Relay.Server)
	collected := make(map[string][]byte)
	start := time.Now()
	for len(collected) < expected {
		if time.Since(start) > time.Minute {
			return nil, fmt.Errorf("timeout waiting for messages (msgID: %s)", msgID)
		}
		messages, dlErr := relayClient.DownloadMessages(sessionID, localPartyID, msgID)
		if dlErr != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		for _, m := range messages {
			if m.From == localPartyID {
				continue
			}
			if _, exists := collected[m.From]; exists {
				continue
			}
			body, decErr := t.decodeDecryptMessage(m.Body, hexEncryptionKey)
			if decErr != nil {
				continue
			}
			collected[m.From] = body
			_ = relayClient.DeleteMessageFromServer(sessionID, localPartyID, m.Hash, msgID)
		}
		if len(collected) < expected {
			time.Sleep(100 * time.Millisecond)
		}
	}
	return collected, nil
}

func findChainKeyshare(vault *vaultType.Vault, chain string) (string, string, error) {
	pubKey := ""
	for _, cpk := range vault.ChainPublicKeys {
		if strings.EqualFold(cpk.Chain, chain) {
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
