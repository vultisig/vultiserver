package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	keygen "github.com/vultisig/commondata/go/vultisig/keygen/v1"
	vaultType "github.com/vultisig/commondata/go/vultisig/vault/v1"

	"github.com/vultisig/vultiserver/internal/types"
	"github.com/vultisig/vultiserver/relay"
)

var protocolChainName = map[string]string{
	"frozt": "ZcashSapling",
	"fromt": "Monero",
}

func (t *DKLSTssService) ProcessBatchKeygen(req types.BatchVaultRequest) (*KeygenResult, error) {
	var existingVault *vaultType.Vault
	protocolsToRun := req.Protocols
	isAppend := req.PublicKey != ""

	if isAppend {
		accessor, err := relay.NewLocalStateAccessorImp(
			t.cfg.Server.VaultsFilePath, req.PublicKey, req.EncryptionPassword, t.blockStorage)
		if err != nil {
			return nil, fmt.Errorf("failed to load vault: %w", err)
		}
		existingVault = accessor.Vault
		if req.LocalPartyId == "" {
			req.LocalPartyId = existingVault.LocalPartyId
		}
		if req.LocalPartyId == "" {
			return nil, fmt.Errorf("local_party_id is required")
		}
		protocolsToRun = filterNewProtocols(req.Protocols, existingVault)
		if len(protocolsToRun) == 0 {
			return allSkippedResult(req.Protocols), nil
		}
	}

	serverURL := t.cfg.Relay.Server
	relayClient := relay.NewRelayClient(serverURL)

	err := relayClient.RegisterSessionWithRetry(req.SessionID, req.LocalPartyId)
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
		"sessionID":  req.SessionID,
		"parties":    partiesJoined,
		"protocols":  protocolsToRun,
		"isAppend":   isAppend,
	}).Info("Batch keygen session started")

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

	protocols, err := t.initProtocols(protocolsToRun, setupMsg, req.LocalPartyId, partiesJoined, relayClient, req.SessionID, req.HexEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to init protocols: %w", err)
	}
	defer freeProtocols(protocols)

	t.runKeygen(protocols, req.SessionID, req.HexEncryptionKey, req.LocalPartyId, partiesJoined)

	if !isAppend {
		for _, p := range protocols {
			if p.Name() == "ecdsa" && !p.IsFinished() {
				return nil, fmt.Errorf("ecdsa keygen failed — cannot create vault")
			}
		}
	}

	_, checkErr := relayClient.CheckCompletedParties(req.SessionID, partiesJoined)
	if checkErr != nil {
		t.logger.WithFields(logrus.Fields{
			"session": req.SessionID,
			"error":   checkErr,
		}).Error("Failed to check completed parties")
	}

	result := t.collectResults(protocols, req.Protocols, protocolsToRun)

	if len(protocolsToRun) > 0 && !hasAnySuccess(result) {
		return result, fmt.Errorf("all requested protocols failed")
	}

	if t.backup != nil && hasAnySuccess(result) {
		backupErr := t.saveVault(req, partiesJoined, existingVault, result)
		if backupErr != nil {
			if !isAppend {
				return nil, fmt.Errorf("failed to store new vault: %w", backupErr)
			}
			t.logger.WithFields(logrus.Fields{
				"error": backupErr,
			}).Warn("failed to store appended vault, existing vault is intact")
			return result, fmt.Errorf("vault append storage failed: %w", backupErr)
		}
	}

	return result, nil
}

func filterNewProtocols(requested []string, vault *vaultType.Vault) []string {
	var needed []string
	for _, name := range requested {
		if protocolPublicKey(vault, name) != "" {
			continue
		}
		needed = append(needed, name)
	}
	return needed
}

func protocolPublicKey(vault *vaultType.Vault, protocol string) string {
	switch protocol {
	case "ecdsa":
		return vault.PublicKeyEcdsa
	case "eddsa":
		return vault.PublicKeyEddsa
	case "mldsa":
		return vault.PublicKeyMldsa44
	default:
		chainName := protocolChainName[protocol]
		if chainName == "" {
			return ""
		}
		for _, cpk := range vault.ChainPublicKeys {
			if cpk.Chain == chainName {
				return cpk.PublicKey
			}
		}
		return ""
	}
}

func allSkippedResult(requested []string) *KeygenResult {
	result := &KeygenResult{
		phaseResults: make(map[string]*PhaseResult),
	}
	for _, name := range requested {
		result.Phases = append(result.Phases, KeygenPhaseStatus{
			Name:    name,
			Skipped: true,
		})
	}
	return result
}

func hasAnySuccess(result *KeygenResult) bool {
	return len(result.phaseResults) > 0
}

func (t *DKLSTssService) initProtocols(
	names []string, setupMsg []byte, localPartyID string, parties []string,
	relayClient *relay.Client, sessionID, hexEncryptionKey string,
) ([]KeygenProtocol, error) {
	var protocols []KeygenProtocol
	for _, name := range names {
		protocolSetupMsg := setupMsg
		if name == "mldsa" {
			mldsaSetup, err := t.fetchProtocolSetupMessage(relayClient, sessionID, hexEncryptionKey, "p-mldsa-setup")
			if err != nil {
				freeProtocols(protocols)
				return nil, fmt.Errorf("init %s: %w", name, err)
			}
			protocolSetupMsg = mldsaSetup
		}
		p, err := t.initProtocol(name, protocolSetupMsg, localPartyID, parties)
		if err != nil {
			freeProtocols(protocols)
			return nil, fmt.Errorf("init %s: %w", name, err)
		}
		protocols = append(protocols, p)
	}
	return protocols, nil
}

func (t *DKLSTssService) fetchProtocolSetupMessage(
	relayClient *relay.Client, sessionID, hexEncryptionKey, messageID string,
) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	encryptedMsg, err := relayClient.WaitForSetupMessage(ctx, sessionID, messageID)
	if err != nil {
		return nil, fmt.Errorf("failed to get setup message for %s: %w", messageID, err)
	}
	return t.decodeDecryptMessage(encryptedMsg, hexEncryptionKey)
}

func (t *DKLSTssService) initProtocol(name string, setupMsg []byte, localPartyID string, parties []string) (KeygenProtocol, error) {
	switch name {
	case "ecdsa":
		return NewMPCKeygenProtocol("ecdsa", "p-ecdsa", setupMsg, localPartyID, false, false)
	case "eddsa":
		return NewMPCKeygenProtocol("eddsa", "p-eddsa", setupMsg, localPartyID, true, false)
	case "frozt":
		return NewFroztKeygenProtocol("frozt", "p-frozt", localPartyID, parties)
	case "fromt":
		return NewFromtKeygenProtocol("fromt", "p-fromt", localPartyID, parties)
	case "mldsa":
		return NewMPCKeygenProtocol("mldsa", "p-mldsa", setupMsg, localPartyID, true, true)
	default:
		return nil, fmt.Errorf("unknown protocol: %s", name)
	}
}

func freeProtocols(protocols []KeygenProtocol) {
	for _, p := range protocols {
		_ = p.Free()
	}
}

func (t *DKLSTssService) runKeygen(
	protocols []KeygenProtocol,
	sessionID, hexEncryptionKey, localPartyID string,
	parties []string,
) {
	ctx, cancel := context.WithTimeout(context.Background(), KeygenTimeout)
	defer cancel()

	relayServer := t.cfg.Relay.Server
	sendFn := func(msgID string, msgs []OutboundMsg, sid, encKey, localID string, pts []string) error {
		return encryptAndSendMessages(relayServer, sid, encKey, true, msgID, msgs, localID, pts)
	}
	notifyFn := notifyStatusViaRelay(sendFn, sessionID, hexEncryptionKey, localPartyID, parties, t.logger)

	ex := ProtocolExchanger{
		RelayClient:      relay.NewRelayClient(relayServer),
		RelayServer:      relayServer,
		SessionID:        sessionID,
		HexEncryptionKey: hexEncryptionKey,
		LocalPartyID:     localPartyID,
		Parties:          parties,
		DecryptFn:        t.decodeDecryptMessage,
		SendFn:           sendFn,
		NotifyFn:         notifyFn,
		Logger:           t.logger,
	}

	var wg sync.WaitGroup
	for _, p := range protocols {
		wg.Add(1)
		go func(p KeygenProtocol) {
			defer wg.Done()
			runProtocolExchange(ctx, p, ex)
		}(p)
	}
	wg.Wait()

	t.logger.Info("all protocol goroutines finished")
}

func (t *DKLSTssService) collectResults(protocols []KeygenProtocol, allRequested, actuallyRan []string) *KeygenResult {
	result := &KeygenResult{
		phaseResults: make(map[string]*PhaseResult),
	}

	ranSet := make(map[string]bool)
	for _, name := range actuallyRan {
		ranSet[name] = true
	}

	for _, name := range allRequested {
		if !ranSet[name] {
			result.Phases = append(result.Phases, KeygenPhaseStatus{
				Name:    name,
				Skipped: true,
			})
			continue
		}

		status := KeygenPhaseStatus{Name: name}
		for _, p := range protocols {
			if p.Name() != name {
				continue
			}
			if p.IsFinished() {
				phaseResult, err := p.Result()
				if err != nil {
					status.Error = err.Error()
				} else {
					status.Success = true
					status.PublicKey = phaseResult.PublicKey
					result.phaseResults[name] = phaseResult
					if name == "ecdsa" {
						result.ECDSAPublicKey = phaseResult.PublicKey
					}
					if name == "eddsa" {
						result.EDDSAPublicKey = phaseResult.PublicKey
					}
					if name == "mldsa" {
						result.MLDSAPublicKey = phaseResult.PublicKey
					}
				}
			} else {
				status.Error = "did not complete within timeout"
			}
			break
		}
		result.Phases = append(result.Phases, status)
	}
	return result
}

func (t *DKLSTssService) saveVault(
	req types.BatchVaultRequest,
	partiesJoined []string,
	existingVault *vaultType.Vault,
	result *KeygenResult,
) error {
	var vault *vaultType.Vault

	if existingVault != nil {
		vault = proto.Clone(existingVault).(*vaultType.Vault)
	} else {
		ecdsaResult := result.phaseResults["ecdsa"]
		if ecdsaResult == nil {
			return fmt.Errorf("ecdsa result required for new vault")
		}
		vault = &vaultType.Vault{
			Name:           req.Name,
			PublicKeyEcdsa: ecdsaResult.PublicKey,
			Signers:        partiesJoined,
			CreatedAt:      timestamppb.New(time.Now()),
			HexChainCode:   ecdsaResult.ChainCode,
			LocalPartyId:   req.LocalPartyId,
			ResharePrefix:  "",
		}

		switch req.LibType {
		case types.DKLS:
			vault.LibType = keygen.LibType_LIB_TYPE_DKLS
		case types.GG20:
			vault.LibType = keygen.LibType_LIB_TYPE_GG20
		default:
			vault.LibType = keygen.LibType_LIB_TYPE_DKLS
		}
	}

	for name, pr := range result.phaseResults {
		vault.KeyShares = append(vault.KeyShares,
			&vaultType.Vault_KeyShare{PublicKey: pr.PublicKey, Keyshare: pr.Keyshare},
		)

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
				vault.ChainPublicKeys = append(vault.ChainPublicKeys,
					&vaultType.Vault_ChainPublicKey{Chain: chainName, PublicKey: pr.PublicKey},
				)
			}
		}
	}

	return t.backup.SaveVaultAndScheduleEmail(vault, req.EncryptionPassword, req.Email)
}
