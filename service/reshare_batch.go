package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	keygen "github.com/vultisig/commondata/go/vultisig/keygen/v1"
	vaultType "github.com/vultisig/commondata/go/vultisig/vault/v1"
	fromt "github.com/vultisig/frost-zm/go/fromt"
	frozt "github.com/vultisig/frost-zm/go/frozt"

	"github.com/vultisig/vultiserver/common"
	"github.com/vultisig/vultiserver/internal/types"
	"github.com/vultisig/vultiserver/relay"
)

func (t *DKLSTssService) ProcessBatchReshare(req types.BatchReshareRequest) (*KeygenResult, error) {
	accessor, err := relay.NewLocalStateAccessorImp(
		t.cfg.Server.VaultsFilePath, req.PublicKey, req.EncryptionPassword, t.blockStorage)
	if err != nil {
		return nil, fmt.Errorf("failed to load vault: %w", err)
	}
	vault := accessor.Vault

	if req.LocalPartyId == "" {
		req.LocalPartyId = vault.LocalPartyId
	}
	if req.LocalPartyId == "" {
		return nil, fmt.Errorf("local_party_id is required")
	}

	err = validateReshareProtocols(req.Protocols, vault)
	if err != nil {
		return nil, err
	}
	protocolsToRun := req.Protocols

	serverURL := t.cfg.Relay.Server
	relayClient := relay.NewRelayClient(serverURL)

	err = relayClient.RegisterSessionWithRetry(req.SessionID, req.LocalPartyId)
	if err != nil {
		return nil, fmt.Errorf("failed to register session: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	partiesJoined, err := relayClient.WaitForSessionStart(ctx, req.SessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to wait for session start: %w", err)
	}

	t.logger.WithFields(logrus.Fields{
		"sessionID": req.SessionID,
		"parties":   partiesJoined,
		"protocols": protocolsToRun,
	}).Info("Batch reshare session started")

	sortedParties := make([]string, len(partiesJoined))
	copy(sortedParties, partiesJoined)
	sort.Strings(sortedParties)
	isCreator := sortedParties[0] == req.LocalPartyId

	if isCreator {
		err = t.createAndUploadReshareSetups(protocolsToRun, vault, partiesJoined, req, relayClient)
		if err != nil {
			return nil, fmt.Errorf("failed to create reshare setups: %w", err)
		}
	}

	protocols, err := t.initReshareProtocols(protocolsToRun, req.LocalPartyId, vault, relayClient, req.SessionID, req.HexEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to init reshare protocols: %w", err)
	}
	defer freeProtocols(protocols)

	t.runKeygen(protocols, req.SessionID, req.HexEncryptionKey, req.LocalPartyId, partiesJoined)

	result := t.collectResults(protocols, req.Protocols, protocolsToRun)

	if !allSucceeded(result, protocolsToRun) {
		return result, fmt.Errorf("reshare failed: all protocols must complete successfully")
	}

	if t.backup != nil {
		backupErr := t.saveResharedVault(req, partiesJoined, vault, result)
		if backupErr != nil {
			return nil, fmt.Errorf("failed to store reshared vault: %w", backupErr)
		}
	}

	completeErr := relayClient.CompleteSession(req.SessionID, req.LocalPartyId)
	if completeErr != nil {
		t.logger.WithField("error", completeErr).Warn("failed to complete session")
	}

	return result, nil
}

func validateReshareProtocols(requested []string, vault *vaultType.Vault) error {
	if len(requested) == 0 {
		return fmt.Errorf("protocols list is required for reshare")
	}
	for _, name := range requested {
		if protocolPublicKey(vault, name) == "" {
			return fmt.Errorf("vault does not have protocol %s — cannot reshare", name)
		}
	}
	return nil
}

func allSucceeded(result *KeygenResult, protocols []string) bool {
	for _, name := range protocols {
		pr := result.phaseResults[name]
		if pr == nil {
			return false
		}
	}
	return true
}

func (t *DKLSTssService) initReshareProtocols(
	names []string, localPartyID string,
	vault *vaultType.Vault,
	relayClient *relay.Client, sessionID, hexEncryptionKey string,
) ([]KeygenProtocol, error) {
	var protocols []KeygenProtocol
	for _, name := range names {
		setupMsg, fetchErr := t.fetchProtocolSetupMessage(relayClient, sessionID, hexEncryptionKey, "p-"+name+"-reshare-setup")
		if fetchErr != nil {
			freeProtocols(protocols)
			return nil, fmt.Errorf("init reshare %s: %w", name, fetchErr)
		}

		keyshareBytes, err := getVaultKeyshare(vault, name)
		if err != nil {
			freeProtocols(protocols)
			return nil, fmt.Errorf("get keyshare for %s: %w", name, err)
		}

		p, err := t.initReshareProtocol(name, setupMsg, localPartyID, keyshareBytes)
		if err != nil {
			freeProtocols(protocols)
			return nil, fmt.Errorf("init reshare %s: %w", name, err)
		}
		protocols = append(protocols, p)
	}
	return protocols, nil
}

func (t *DKLSTssService) createAndUploadReshareSetups(
	protocols []string,
	vault *vaultType.Vault,
	parties []string,
	req types.BatchReshareRequest,
	relayClient *relay.Client,
) error {
	oldIndices := mapPartyIndices(parties, req.OldParties)
	newIndices := allIndices(len(parties))
	frostParties := buildFrostPartyInfo(parties)
	oldFrostIDs := mapOldFrostIDs(req.OldParties, parties)

	for _, name := range protocols {
		setupMsg, err := t.buildReshareSetupMessage(name, vault, parties, frostParties, oldFrostIDs, oldIndices, newIndices)
		if err != nil {
			return err
		}

		encrypted, err := encodeEncryptMessage(setupMsg, req.HexEncryptionKey)
		if err != nil {
			return fmt.Errorf("encrypt reshare setup for %s: %w", name, err)
		}

		messageID := "p-" + name + "-reshare-setup"
		err = relayClient.UploadSetupMessage(req.SessionID, messageID, encrypted)
		if err != nil {
			return fmt.Errorf("upload reshare setup for %s: %w", name, err)
		}

		t.logger.WithFields(logrus.Fields{
			"protocol":  name,
			"messageID": messageID,
		}).Info("Uploaded reshare setup message")
	}
	return nil
}

func (t *DKLSTssService) buildReshareSetupMessage(
	name string,
	vault *vaultType.Vault,
	parties []string,
	frostParties []frozt.PartyInfo,
	oldFrostIDs []uint16,
	oldIndices []int,
	newIndices []int,
) ([]byte, error) {
	switch name {
	case "ecdsa", "eddsa":
		isEdDSA := name == "eddsa"
		wrapper := NewMPCWrapperImp(isEdDSA, false)

		keyshareBytes, err := getVaultKeyshare(vault, name)
		if err != nil {
			return nil, fmt.Errorf("get keyshare for QC setup %s: %w", name, err)
		}

		keyshareHandle, err := wrapper.KeyshareFromBytes(keyshareBytes)
		if err != nil {
			return nil, fmt.Errorf("load keyshare for QC setup %s: %w", name, err)
		}
		defer func() {
			if freeErr := wrapper.KeyshareFree(keyshareHandle); freeErr != nil {
				t.logger.WithError(freeErr).Warnf("failed to free QC keyshare handle for %s", name)
			}
		}()

		setupMsg, err := wrapper.QcSetupMsgNew(keyshareHandle, len(parties), parties, oldIndices, newIndices)
		if err != nil {
			return nil, fmt.Errorf("create QC setup for %s: %w", name, err)
		}
		return setupMsg, nil
	case "frozt":
		keyshareBytes, err := getVaultKeyshare(vault, name)
		if err != nil {
			return nil, fmt.Errorf("get keyshare for %s reshare setup: %w", name, err)
		}
		pubKeyPackage, err := frozt.KeyShareBundlePubKeyPackage(keyshareBytes)
		if err != nil {
			return nil, fmt.Errorf("frozt unpack pubkey package: %w", err)
		}
		expectedVK, err := frozt.PubKeyPackageVerifyingKey(pubKeyPackage)
		if err != nil {
			return nil, fmt.Errorf("frozt verifying key: %w", err)
		}
		setupMsg, err := frozt.ReshareSetupMsgNew(
			uint16(len(frostParties)),
			uint16(getReshareThreshold(len(frostParties))),
			frostParties,
			oldFrostIDs,
			expectedVK,
		)
		if err != nil {
			return nil, fmt.Errorf("create frozt reshare setup: %w", err)
		}
		return setupMsg, nil
	case "fromt":
		keyshareBytes, err := getVaultKeyshare(vault, name)
		if err != nil {
			return nil, fmt.Errorf("get keyshare for %s reshare setup: %w", name, err)
		}
		expectedVK, err := fromt.KeySharePublicKey(keyshareBytes)
		if err != nil {
			return nil, fmt.Errorf("fromt public key: %w", err)
		}
		fromtParties := make([]fromt.PartyInfo, len(frostParties))
		for i, party := range frostParties {
			fromtParties[i] = fromt.PartyInfo{FrostID: party.FrostID, Name: party.Name}
		}
		setupMsg, err := fromt.ReshareSetupMsgNew(
			uint16(len(fromtParties)),
			uint16(getReshareThreshold(len(fromtParties))),
			fromtParties,
			oldFrostIDs,
			expectedVK,
		)
		if err != nil {
			return nil, fmt.Errorf("create fromt reshare setup: %w", err)
		}
		return setupMsg, nil
	default:
		return nil, fmt.Errorf("reshare not supported for protocol: %s", name)
	}
}

func encodeEncryptMessage(msg []byte, hexEncryptionKey string) (string, error) {
	inner := base64.StdEncoding.EncodeToString(msg)
	encrypted, err := common.EncryptGCM([]byte(inner), hexEncryptionKey)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func mapPartyIndices(allParties []string, subset []string) []int {
	indexMap := make(map[string]int)
	for i, p := range allParties {
		indexMap[p] = i
	}
	var indices []int
	for _, p := range subset {
		if idx, ok := indexMap[p]; ok {
			indices = append(indices, idx)
		}
	}
	return indices
}

func allIndices(n int) []int {
	indices := make([]int, n)
	for i := range indices {
		indices[i] = i
	}
	return indices
}

func buildFrostPartyInfo(parties []string) []frozt.PartyInfo {
	sorted := append([]string(nil), parties...)
	sort.Strings(sorted)
	info := make([]frozt.PartyInfo, len(sorted))
	for i, party := range sorted {
		info[i] = frozt.PartyInfo{
			FrostID: uint16(i + 1),
			Name:    []byte(party),
		}
	}
	return info
}

func mapOldFrostIDs(oldParties []string, currentParties []string) []uint16 {
	currentSet := make(map[string]bool, len(currentParties))
	for _, party := range currentParties {
		currentSet[party] = true
	}

	sortedOld := append([]string(nil), oldParties...)
	sort.Strings(sortedOld)

	var ids []uint16
	for i, party := range sortedOld {
		if currentSet[party] {
			ids = append(ids, uint16(i+1))
		}
	}
	return ids
}

func getReshareThreshold(signers int) int {
	return (signers*2 + 2) / 3
}

func (t *DKLSTssService) initReshareProtocol(
	name string, setupMsg []byte, localPartyID string, keyshareBytes []byte,
) (KeygenProtocol, error) {
	switch name {
	case "ecdsa":
		return NewMPCReshareProtocol("ecdsa", "p-ecdsa", setupMsg, localPartyID, keyshareBytes, false)
	case "eddsa":
		return NewMPCReshareProtocol("eddsa", "p-eddsa", setupMsg, localPartyID, keyshareBytes, true)
	case "frozt":
		return NewFroztReshareProtocol("frozt", "p-frozt", setupMsg, localPartyID, keyshareBytes)
	case "fromt":
		return NewFromtReshareProtocol("fromt", "p-fromt", setupMsg, localPartyID, keyshareBytes)
	default:
		return nil, fmt.Errorf("reshare not supported for protocol: %s", name)
	}
}

func getVaultKeyshare(vault *vaultType.Vault, protocol string) ([]byte, error) {
	publicKey := protocolPublicKey(vault, protocol)
	if publicKey == "" {
		return nil, fmt.Errorf("no public key found for %s", protocol)
	}

	for _, ks := range vault.KeyShares {
		if ks.PublicKey == publicKey {
			decoded, err := base64.StdEncoding.DecodeString(ks.Keyshare)
			if err != nil {
				return nil, fmt.Errorf("failed to decode %s keyshare: %w", protocol, err)
			}
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("keyshare not found for %s (public_key=%s)", protocol, publicKey)
}

func (t *DKLSTssService) saveResharedVault(
	req types.BatchReshareRequest,
	partiesJoined []string,
	existingVault *vaultType.Vault,
	result *KeygenResult,
) error {
	vault := proto.Clone(existingVault).(*vaultType.Vault)
	vault.Signers = partiesJoined
	vault.CreatedAt = timestamppb.Now()
	vault.LibType = keygen.LibType_LIB_TYPE_DKLS

	for name, pr := range result.phaseResults {
		oldPubKey := protocolPublicKey(existingVault, name)
		replaced := false
		for i, ks := range vault.KeyShares {
			if ks.PublicKey == oldPubKey {
				vault.KeyShares[i] = &vaultType.Vault_KeyShare{
					PublicKey: pr.PublicKey,
					Keyshare:  pr.Keyshare,
				}
				replaced = true
				break
			}
		}
		if !replaced {
			vault.KeyShares = append(vault.KeyShares,
				&vaultType.Vault_KeyShare{PublicKey: pr.PublicKey, Keyshare: pr.Keyshare},
			)
		}

		switch name {
		case "ecdsa":
			vault.PublicKeyEcdsa = pr.PublicKey
			vault.HexChainCode = pr.ChainCode
		case "eddsa":
			vault.PublicKeyEddsa = pr.PublicKey
		case "mldsa":
			vault.PublicKeyMldsa44 = pr.PublicKey
		case "frozt":
			vault.PublicKeyFrozt = pr.PublicKey
			if err := setFroztVaultEntries(vault, pr.PublicKey, pr.Keyshare); err != nil {
				return err
			}
		case "fromt":
			vault.PublicKeyFromt = pr.PublicKey
			setFromtVaultEntries(vault, pr.PublicKey)
		}
	}

	return t.backup.SaveVaultAndScheduleEmail(vault, req.EncryptionPassword, req.Email)
}
