package service

import (
	"encoding/base64"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	frozt "github.com/vultisig/frost-zm/go/frozt"
	"github.com/vultisig/vultiserver/relay"
)

type FroztResult struct {
	Keyshare     string
	VerifyingKey string
}

func (t *DKLSTssService) getFrostId(localPartyID string, parties []string) uint16 {
	sorted := make([]string, len(parties))
	copy(sorted, parties)
	sort.Strings(sorted)
	for i, p := range sorted {
		if p == localPartyID {
			return uint16(i + 1)
		}
	}
	return 0
}

func (t *DKLSTssService) getPartyForFrostId(frostId uint16, parties []string) string {
	sorted := make([]string, len(parties))
	copy(sorted, parties)
	sort.Strings(sorted)
	idx := int(frostId) - 1
	if idx < 0 || idx >= len(sorted) {
		return ""
	}
	return sorted[idx]
}

func (t *DKLSTssService) getKeygenThreshold(n int) int {
	return n
}

func (t *DKLSTssService) froztBroadcast(
	sessionID string,
	hexEncryptionKey string,
	localPartyID string,
	parties []string,
	data []byte,
	messageID string,
) error {
	body := base64.StdEncoding.EncodeToString(data)
	messenger := relay.NewMessenger(t.cfg.Relay.Server, sessionID, hexEncryptionKey, true, messageID)
	for _, peer := range parties {
		if peer == localPartyID {
			continue
		}
		err := messenger.Send(localPartyID, peer, body)
		if err != nil {
			return fmt.Errorf("frozt broadcast to %s failed: %w", peer, err)
		}
	}
	return nil
}

func (t *DKLSTssService) froztSendToParty(
	sessionID string,
	hexEncryptionKey string,
	localPartyID string,
	targetPartyID string,
	data []byte,
	messageID string,
) error {
	body := base64.StdEncoding.EncodeToString(data)
	messenger := relay.NewMessenger(t.cfg.Relay.Server, sessionID, hexEncryptionKey, true, messageID)
	err := messenger.Send(localPartyID, targetPartyID, body)
	if err != nil {
		return fmt.Errorf("frozt send to %s failed: %w", targetPartyID, err)
	}
	return nil
}

func (t *DKLSTssService) froztCollectMessages(
	sessionID string,
	hexEncryptionKey string,
	localPartyID string,
	messageID string,
	expectedCount int,
	timeout time.Duration,
) (map[string][]byte, error) {
	relayClient := relay.NewRelayClient(t.cfg.Relay.Server)
	collected := make(map[string][]byte)
	var seen sync.Map
	start := time.Now()

	for len(collected) < expectedCount {
		if time.Since(start) > timeout {
			return nil, fmt.Errorf("frozt: timeout collecting messages for %s, got %d/%d", messageID, len(collected), expectedCount)
		}

		messages, err := relayClient.DownloadMessages(sessionID, localPartyID, messageID)
		if err != nil {
			t.logger.WithFields(logrus.Fields{
				"messageID": messageID,
				"error":     err,
			}).Error("frozt: failed to download messages")
			time.Sleep(100 * time.Millisecond)
			continue
		}

		for _, msg := range messages {
			if msg.From == localPartyID {
				continue
			}
			cacheKey := fmt.Sprintf("%s-%s-%s", sessionID, msg.From, msg.Hash)
			if _, found := seen.Load(cacheKey); found {
				continue
			}
			seen.Store(cacheKey, struct{}{})

			decrypted, err := t.decodeDecryptMessage(msg.Body, hexEncryptionKey)
			if err != nil {
				t.logger.WithFields(logrus.Fields{
					"from":  msg.From,
					"error": err,
				}).Error("frozt: failed to decrypt message")
				continue
			}

			collected[msg.From] = decrypted

			deleteErr := relayClient.DeleteMessageFromServer(sessionID, localPartyID, msg.Hash, messageID)
			if deleteErr != nil {
				t.logger.WithFields(logrus.Fields{
					"hash":  msg.Hash,
					"error": deleteErr,
				}).Error("frozt: failed to delete message")
			}
		}

		if len(collected) < expectedCount {
			time.Sleep(100 * time.Millisecond)
		}
	}

	return collected, nil
}

func (t *DKLSTssService) buildFrostMap(partyDataMap map[string][]byte, parties []string) []byte {
	entries := make([]frozt.MapEntry, 0, len(partyDataMap))
	for partyID, data := range partyDataMap {
		frostId := t.getFrostId(partyID, parties)
		if frostId == 0 {
			continue
		}
		entries = append(entries, frozt.MapEntry{ID: frostId, Value: data})
	}
	return frozt.EncodeMap(entries)
}

func (t *DKLSTssService) exchangeMetadata(
	sessionID string,
	hexEncryptionKey string,
	localPartyID string,
	parties []string,
	isCoordinator bool,
	existingExtras []byte,
	birthday uint64,
	timeout time.Duration,
) ([]byte, uint64, error) {
	peerCount := len(parties) - 1

	var metadataBytes []byte
	var err error
	if isCoordinator {
		if len(existingExtras) > 0 {
			metadataBytes, err = frozt.KeygenMetadataCreateWithExtras(existingExtras, birthday)
		} else {
			_, metadataBytes, err = frozt.KeygenMetadataCreate(birthday)
		}
		if err != nil {
			return nil, 0, fmt.Errorf("frozt create metadata failed: %w", err)
		}
		err = t.froztBroadcast(sessionID, hexEncryptionKey, localPartyID, parties, metadataBytes, "frozt-metadata")
		if err != nil {
			return nil, 0, fmt.Errorf("frozt broadcast metadata failed: %w", err)
		}
	} else {
		messages, err := t.froztCollectMessages(sessionID, hexEncryptionKey, localPartyID, "frozt-metadata", 1, timeout)
		if err != nil {
			return nil, 0, fmt.Errorf("frozt collect metadata failed: %w", err)
		}
		for _, v := range messages {
			metadataBytes = v
			break
		}
	}

	metadataHash, err := frozt.KeygenMetadataHash(metadataBytes)
	if err != nil {
		return nil, 0, fmt.Errorf("frozt hash metadata failed: %w", err)
	}
	err = t.froztBroadcast(sessionID, hexEncryptionKey, localPartyID, parties, metadataHash, "frozt-metadata-hash")
	if err != nil {
		return nil, 0, fmt.Errorf("frozt broadcast metadata-hash failed: %w", err)
	}

	peerHashes, err := t.froztCollectMessages(sessionID, hexEncryptionKey, localPartyID, "frozt-metadata-hash", peerCount, timeout)
	if err != nil {
		return nil, 0, fmt.Errorf("frozt collect metadata-hash failed: %w", err)
	}

	myHashHex := fmt.Sprintf("%x", metadataHash)
	for partyID, peerHash := range peerHashes {
		peerHashHex := fmt.Sprintf("%x", peerHash)
		if peerHashHex != myHashHex {
			return nil, 0, fmt.Errorf("frozt metadata hash mismatch with %s", partyID)
		}
	}

	extras, parsedBirthday, err := frozt.KeygenMetadataParse(metadataBytes)
	if err != nil {
		return nil, 0, fmt.Errorf("frozt parse metadata failed: %w", err)
	}

	return extras, parsedBirthday, nil
}

func (t *DKLSTssService) froztKeygen(
	sessionID string,
	hexEncryptionKey string,
	localPartyID string,
	parties []string,
) (*FroztResult, error) {
	myId := t.getFrostId(localPartyID, parties)
	if myId == 0 {
		return nil, fmt.Errorf("frozt: local party %s not found in parties list", localPartyID)
	}
	maxSigners := uint16(len(parties))
	minSigners := uint16(t.getKeygenThreshold(len(parties)))
	peerCount := len(parties) - 1
	timeout := 2 * time.Minute

	t.logger.WithFields(logrus.Fields{
		"sessionID":  sessionID,
		"partyID":    localPartyID,
		"frostId":    myId,
		"maxSigners": maxSigners,
		"minSigners": minSigners,
	}).Info("frozt DKG starting")

	secret1, r1Package, err := frozt.DkgPart1(myId, maxSigners, minSigners)
	if err != nil {
		return nil, fmt.Errorf("frozt DkgPart1 failed: %w", err)
	}

	err = t.froztBroadcast(sessionID, hexEncryptionKey, localPartyID, parties, r1Package, "frozt-r1")
	if err != nil {
		return nil, fmt.Errorf("frozt broadcast r1 failed: %w", err)
	}

	r1Messages, err := t.froztCollectMessages(sessionID, hexEncryptionKey, localPartyID, "frozt-r1", peerCount, timeout)
	if err != nil {
		return nil, fmt.Errorf("frozt collect r1 failed: %w", err)
	}
	r1Map := t.buildFrostMap(r1Messages, parties)

	secret2, r2PackagesEncoded, err := frozt.DkgPart2(secret1, r1Map)
	if err != nil {
		return nil, fmt.Errorf("frozt DkgPart2 failed: %w", err)
	}

	r2Packages, err := frozt.DecodeMap(r2PackagesEncoded)
	if err != nil {
		return nil, fmt.Errorf("frozt DecodeMap r2 failed: %w", err)
	}

	for _, entry := range r2Packages {
		targetPartyID := t.getPartyForFrostId(entry.ID, parties)
		if targetPartyID == "" || targetPartyID == localPartyID {
			continue
		}
		err = t.froztSendToParty(sessionID, hexEncryptionKey, localPartyID, targetPartyID, entry.Value, "frozt-r2")
		if err != nil {
			return nil, fmt.Errorf("frozt send r2 to %s failed: %w", targetPartyID, err)
		}
	}

	r2Messages, err := t.froztCollectMessages(sessionID, hexEncryptionKey, localPartyID, "frozt-r2", peerCount, timeout)
	if err != nil {
		return nil, fmt.Errorf("frozt collect r2 failed: %w", err)
	}
	r2Map := t.buildFrostMap(r2Messages, parties)

	keyPackage, pubKeyPackage, err := frozt.DkgPart3(secret2, r1Map, r2Map)
	if err != nil {
		return nil, fmt.Errorf("frozt DkgPart3 failed: %w", err)
	}

	saplingExtras, birthday, err := t.exchangeMetadata(sessionID, hexEncryptionKey, localPartyID, parties, false, nil, 0, timeout)
	if err != nil {
		return nil, fmt.Errorf("frozt metadata exchange failed: %w", err)
	}

	t.logger.Info("frozt DKG complete")

	bundle, err := frozt.KeyShareBundlePack(keyPackage, pubKeyPackage, saplingExtras, birthday)
	if err != nil {
		return nil, fmt.Errorf("frozt KeyShareBundlePack failed: %w", err)
	}

	vk, err := frozt.PubKeyPackageVerifyingKey(pubKeyPackage)
	if err != nil {
		return nil, fmt.Errorf("frozt PubKeyPackageVerifyingKey failed: %w", err)
	}

	return &FroztResult{
		Keyshare:     base64.StdEncoding.EncodeToString(bundle),
		VerifyingKey: fmt.Sprintf("%x", vk),
	}, nil
}

func (t *DKLSTssService) froztKeygenWithRetry(
	sessionID string,
	hexEncryptionKey string,
	localPartyID string,
	parties []string,
) (*FroztResult, error) {
	for i := 0; i < 3; i++ {
		result, err := t.froztKeygen(sessionID, hexEncryptionKey, localPartyID, parties)
		if err != nil {
			t.logger.WithFields(logrus.Fields{
				"session_id": sessionID,
				"attempt":    i,
				"error":      err,
			}).Error("frozt keygen attempt failed")
			time.Sleep(time.Duration(10*(1<<i)) * time.Millisecond)
			continue
		}
		return result, nil
	}
	return nil, fmt.Errorf("frozt keygen failed after 3 attempts")
}

func (t *DKLSTssService) froztKeyImport(
	sessionID string,
	hexEncryptionKey string,
	localPartyID string,
	parties []string,
) (*FroztResult, error) {
	myId := t.getFrostId(localPartyID, parties)
	if myId == 0 {
		return nil, fmt.Errorf("frozt: local party %s not found in parties list", localPartyID)
	}
	maxSigners := uint16(len(parties))
	minSigners := uint16(t.getKeygenThreshold(len(parties)))
	peerCount := len(parties) - 1
	timeout := 2 * time.Minute

	t.logger.WithFields(logrus.Fields{
		"sessionID":  sessionID,
		"partyID":    localPartyID,
		"frostId":    myId,
		"maxSigners": maxSigners,
		"minSigners": minSigners,
	}).Info("frozt key import starting (server is non-coordinator)")

	secret1, r1Package, _, _, err := frozt.KeyImportPart1(myId, maxSigners, minSigners, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("frozt KeyImportPart1 failed: %w", err)
	}

	err = t.froztBroadcast(sessionID, hexEncryptionKey, localPartyID, parties, r1Package, "frozt-r1")
	if err != nil {
		return nil, fmt.Errorf("frozt broadcast r1 failed: %w", err)
	}

	r1Messages, err := t.froztCollectMessages(sessionID, hexEncryptionKey, localPartyID, "frozt-r1", peerCount, timeout)
	if err != nil {
		return nil, fmt.Errorf("frozt collect r1 failed: %w", err)
	}
	r1Map := t.buildFrostMap(r1Messages, parties)

	secret2, r2PackagesEncoded, err := frozt.DkgPart2(secret1, r1Map)
	if err != nil {
		return nil, fmt.Errorf("frozt DkgPart2 failed: %w", err)
	}

	r2Packages, err := frozt.DecodeMap(r2PackagesEncoded)
	if err != nil {
		return nil, fmt.Errorf("frozt DecodeMap r2 failed: %w", err)
	}

	for _, entry := range r2Packages {
		targetPartyID := t.getPartyForFrostId(entry.ID, parties)
		if targetPartyID == "" || targetPartyID == localPartyID {
			continue
		}
		err = t.froztSendToParty(sessionID, hexEncryptionKey, localPartyID, targetPartyID, entry.Value, "frozt-r2")
		if err != nil {
			return nil, fmt.Errorf("frozt send r2 to %s failed: %w", targetPartyID, err)
		}
	}

	r2Messages, err := t.froztCollectMessages(sessionID, hexEncryptionKey, localPartyID, "frozt-r2", peerCount, timeout)
	if err != nil {
		return nil, fmt.Errorf("frozt collect r2 failed: %w", err)
	}
	r2Map := t.buildFrostMap(r2Messages, parties)

	expectedVkMessages, err := t.froztCollectMessages(sessionID, hexEncryptionKey, localPartyID, "frozt-expected-vk", 1, timeout)
	if err != nil {
		return nil, fmt.Errorf("frozt collect expected-vk failed: %w", err)
	}
	var expectedVk []byte
	for _, v := range expectedVkMessages {
		expectedVk = v
		break
	}

	keyPackage, pubKeyPackage, err := frozt.KeyImportPart3(secret2, r1Map, r2Map, expectedVk)
	if err != nil {
		return nil, fmt.Errorf("frozt KeyImportPart3 failed: %w", err)
	}

	saplingExtras, birthday, err := t.exchangeMetadata(sessionID, hexEncryptionKey, localPartyID, parties, false, nil, 0, timeout)
	if err != nil {
		return nil, fmt.Errorf("frozt metadata exchange failed: %w", err)
	}

	t.logger.Info("frozt key import complete")

	bundle, err := frozt.KeyShareBundlePack(keyPackage, pubKeyPackage, saplingExtras, birthday)
	if err != nil {
		return nil, fmt.Errorf("frozt KeyShareBundlePack failed: %w", err)
	}

	vk, err := frozt.PubKeyPackageVerifyingKey(pubKeyPackage)
	if err != nil {
		return nil, fmt.Errorf("frozt PubKeyPackageVerifyingKey failed: %w", err)
	}

	return &FroztResult{
		Keyshare:     base64.StdEncoding.EncodeToString(bundle),
		VerifyingKey: fmt.Sprintf("%x", vk),
	}, nil
}

func (t *DKLSTssService) froztKeyImportWithRetry(
	sessionID string,
	hexEncryptionKey string,
	localPartyID string,
	parties []string,
) (*FroztResult, error) {
	for i := 0; i < 3; i++ {
		result, err := t.froztKeyImport(sessionID, hexEncryptionKey, localPartyID, parties)
		if err != nil {
			t.logger.WithFields(logrus.Fields{
				"session_id": sessionID,
				"attempt":    i,
				"error":      err,
			}).Error("frozt key import attempt failed")
			time.Sleep(time.Duration(10*(1<<i)) * time.Millisecond)
			continue
		}
		return result, nil
	}
	return nil, fmt.Errorf("frozt key import failed after 3 attempts")
}

