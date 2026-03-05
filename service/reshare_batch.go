package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	keygen "github.com/vultisig/commondata/go/vultisig/keygen/v1"
	vaultType "github.com/vultisig/commondata/go/vultisig/vault/v1"

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

	protocolsToRun := filterReshareProtocols(req.Protocols, vault)
	if len(protocolsToRun) == 0 {
		return nil, fmt.Errorf("no protocols to reshare — requested protocols not found in vault")
	}

	serverURL := t.cfg.Relay.Server
	relayClient := relay.NewRelayClient(serverURL)

	err = relayClient.RegisterSessionWithRetry(req.SessionID, req.LocalPartyId)
	if err != nil {
		return nil, fmt.Errorf("failed to register session: %w", err)
	}
	defer func() {
		completeErr := relayClient.CompleteSession(req.SessionID, req.LocalPartyId)
		if completeErr != nil {
			t.logger.WithFields(logrus.Fields{
				"session": req.SessionID,
				"error":   completeErr,
			}).Warn("failed to complete session")
		}
	}()

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

	setupCtx, setupCancel := context.WithTimeout(context.Background(), time.Minute)
	defer setupCancel()
	encryptedSetupMsg, err := relayClient.WaitForSetupMessage(setupCtx, req.SessionID, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get setup message: %w", err)
	}

	setupMsg, err := t.decodeDecryptMessage(encryptedSetupMsg, req.HexEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode setup message: %w", err)
	}

	protocols, err := t.initReshareProtocols(protocolsToRun, setupMsg, req.LocalPartyId, vault, relayClient, req.SessionID, req.HexEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to init reshare protocols: %w", err)
	}
	defer freeProtocols(protocols)

	t.runKeygen(protocols, req.SessionID, req.HexEncryptionKey, req.LocalPartyId, partiesJoined)

	_, checkErr := relayClient.CheckCompletedParties(req.SessionID, partiesJoined)
	if checkErr != nil {
		t.logger.WithFields(logrus.Fields{
			"session": req.SessionID,
			"error":   checkErr,
		}).Error("Failed to check completed parties")
	}

	result := t.collectResults(protocols, req.Protocols, protocolsToRun)

	if len(protocolsToRun) > 0 && !hasAnySuccess(result) {
		return result, fmt.Errorf("all reshare protocols failed")
	}

	if t.backup != nil && hasAnySuccess(result) {
		backupErr := t.saveResharedVault(req, partiesJoined, vault, result)
		if backupErr != nil {
			return nil, fmt.Errorf("failed to store reshared vault: %w", backupErr)
		}
	}

	return result, nil
}

func filterReshareProtocols(requested []string, vault *vaultType.Vault) []string {
	var valid []string
	for _, name := range requested {
		if vaultHasProtocol(vault, name) {
			valid = append(valid, name)
		}
	}
	return valid
}

func (t *DKLSTssService) initReshareProtocols(
	names []string, setupMsg []byte, localPartyID string,
	vault *vaultType.Vault,
	relayClient *relay.Client, sessionID, hexEncryptionKey string,
) ([]KeygenProtocol, error) {
	var protocols []KeygenProtocol
	for _, name := range names {
		protocolSetupMsg := setupMsg

		if name == "frozt" || name == "fromt" {
			perProtocolSetup, fetchErr := t.fetchProtocolSetupMessage(relayClient, sessionID, hexEncryptionKey, "p-"+name+"-reshare-setup")
			if fetchErr != nil {
				freeProtocols(protocols)
				return nil, fmt.Errorf("init reshare %s: %w", name, fetchErr)
			}
			protocolSetupMsg = perProtocolSetup
		}

		keyshareBytes, err := getVaultKeyshare(vault, name)
		if err != nil {
			freeProtocols(protocols)
			return nil, fmt.Errorf("get keyshare for %s: %w", name, err)
		}

		p, err := t.initReshareProtocol(name, protocolSetupMsg, localPartyID, keyshareBytes)
		if err != nil {
			freeProtocols(protocols)
			return nil, fmt.Errorf("init reshare %s: %w", name, err)
		}
		protocols = append(protocols, p)
	}
	return protocols, nil
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
		default:
			chainName := protocolChainName[name]
			if chainName != "" {
				for i, cpk := range vault.ChainPublicKeys {
					if cpk.Chain == chainName {
						vault.ChainPublicKeys[i].PublicKey = pr.PublicKey
						break
					}
				}
			}
		}
	}

	return t.backup.SaveVaultAndScheduleEmail(vault, req.EncryptionPassword, req.Email)
}
