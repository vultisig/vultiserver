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

var knownProtocols = map[string]bool{
	"ecdsa": true,
	"eddsa": true,
	"frozt": true,
	"fromt": true,
}

var protocolChainName = map[string]string{
	"frozt": "ZcashSapling",
	"fromt": "Monero",
}

func (t *DKLSTssService) ProcessBatchKeygen(req types.BatchVaultRequest) (*KeygenResult, error) {
	for _, name := range req.Protocols {
		if !knownProtocols[name] {
			return nil, fmt.Errorf("unknown protocol: %s", name)
		}
	}

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
		protocolsToRun = filterNewProtocols(req.Protocols, existingVault)
		if len(protocolsToRun) == 0 {
			return allSkippedResult(req.Protocols), nil
		}
	} else {
		if !containsProtocol(req.Protocols, "ecdsa") {
			return nil, fmt.Errorf("ecdsa is required for new vault")
		}
	}

	serverURL := t.cfg.Relay.Server
	relayClient := relay.NewRelayClient(serverURL)

	err := relayClient.RegisterSessionWithRetry(req.SessionID, req.LocalPartyId)
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

	protocols, err := t.initProtocols(protocolsToRun, setupMsg, req.LocalPartyId, partiesJoined)
	if err != nil {
		return nil, fmt.Errorf("failed to init protocols: %w", err)
	}
	defer freeProtocols(protocols)

	t.runKeygenSlots(protocols, req.SessionID, req.HexEncryptionKey, req.LocalPartyId, partiesJoined)

	if !isAppend {
		for _, p := range protocols {
			if p.Name() == "ecdsa" && !p.IsFinished() {
				return nil, fmt.Errorf("ecdsa keygen failed — cannot create vault")
			}
		}
	}

	completeErr := relayClient.CompleteSession(req.SessionID, req.LocalPartyId)
	if completeErr != nil {
		t.logger.WithFields(logrus.Fields{
			"session": req.SessionID,
			"error":   completeErr,
		}).Error("Failed to complete session")
	}

	_, checkErr := relayClient.CheckCompletedParties(req.SessionID, partiesJoined)
	if checkErr != nil {
		t.logger.WithFields(logrus.Fields{
			"session": req.SessionID,
			"error":   checkErr,
		}).Error("Failed to check completed parties")
	}

	result := t.collectResults(protocols, req.Protocols, protocolsToRun)

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
		if vaultHasProtocol(vault, name) {
			continue
		}
		needed = append(needed, name)
	}
	return needed
}

func vaultHasProtocol(vault *vaultType.Vault, name string) bool {
	switch name {
	case "ecdsa":
		return vault.PublicKeyEcdsa != ""
	case "eddsa":
		return vault.PublicKeyEddsa != ""
	case "mldsa":
		return vault.PublicKeyMldsa44 != ""
	case "frozt":
		return vaultHasChain(vault, "ZcashSapling")
	case "fromt":
		return vaultHasChain(vault, "Monero")
	default:
		return false
	}
}

func vaultHasChain(vault *vaultType.Vault, chain string) bool {
	for _, cpk := range vault.ChainPublicKeys {
		if cpk.Chain == chain {
			return true
		}
	}
	return false
}

func containsProtocol(list []string, name string) bool {
	for _, s := range list {
		if s == name {
			return true
		}
	}
	return false
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

func (t *DKLSTssService) initProtocols(names []string, setupMsg []byte, localPartyID string, parties []string) ([]KeygenProtocol, error) {
	var protocols []KeygenProtocol
	for _, name := range names {
		p, err := t.initProtocol(name, setupMsg, localPartyID, parties)
		if err != nil {
			freeProtocols(protocols)
			return nil, fmt.Errorf("init %s: %w", name, err)
		}
		protocols = append(protocols, p)
	}
	return protocols, nil
}

func (t *DKLSTssService) initProtocol(name string, setupMsg []byte, localPartyID string, parties []string) (KeygenProtocol, error) {
	switch name {
	case "ecdsa":
		return NewMPCKeygenProtocol("ecdsa", "p-ecdsa", false, setupMsg, localPartyID, false, false)
	case "eddsa":
		return NewMPCKeygenProtocol("eddsa", "p-eddsa", false, setupMsg, localPartyID, true, false)
	case "frozt":
		return NewFroztKeygenProtocol("frozt", "p-frozt", false, localPartyID, parties)
	case "fromt":
		return NewFromtKeygenProtocol("fromt", "p-fromt", false, localPartyID, parties)
	default:
		return nil, fmt.Errorf("unknown protocol: %s", name)
	}
}

func freeProtocols(protocols []KeygenProtocol) {
	for _, p := range protocols {
		_ = p.Free()
	}
}

func (t *DKLSTssService) runKeygenSlots(
	protocols []KeygenProtocol,
	sessionID, hexEncryptionKey, localPartyID string,
	parties []string,
) {
	relayClient := relay.NewRelayClient(t.cfg.Relay.Server)

	for slot := range MaxKeygenSlots {
		active := filterActive(protocols)
		if len(active) == 0 {
			break
		}

		for _, p := range active {
			outbound, err := p.DrainOutbound(parties)
			if err != nil {
				t.logger.WithFields(logrus.Fields{
					"protocol": p.Name(),
					"slot":     slot,
					"error":    err,
				}).Error("drain outbound failed")
				continue
			}
			t.sendMessages(p.MessageID(), outbound, sessionID, hexEncryptionKey, localPartyID, parties)
		}

		slotDeadline := time.Now().Add(SlotTimeout)
		for time.Now().Before(slotDeadline) {
			progress := false
			for _, p := range active {
				if p.IsFinished() {
					continue
				}
				messages, dlErr := relayClient.DownloadMessages(sessionID, localPartyID, p.MessageID())
				if dlErr != nil {
					continue
				}
				for _, msg := range messages {
					if msg.From == localPartyID {
						continue
					}
					body, decErr := t.decodeDecryptMessage(msg.Body, hexEncryptionKey)
					if decErr != nil {
						_ = relayClient.DeleteMessageFromServer(sessionID, localPartyID, msg.Hash, p.MessageID())
						continue
					}
					finished, procErr := p.ProcessInbound(msg.From, body)
					if procErr != nil {
						t.logger.WithFields(logrus.Fields{
							"protocol": p.Name(),
							"from":     msg.From,
							"error":    procErr,
						}).Warn("process inbound failed")
					}
					_ = relayClient.DeleteMessageFromServer(sessionID, localPartyID, msg.Hash, p.MessageID())
					progress = true
					if finished {
						t.logger.WithFields(logrus.Fields{
							"protocol": p.Name(),
							"slot":     slot,
						}).Info("protocol finished")
						break
					}
				}
				newOutbound, drainErr := p.DrainOutbound(parties)
				if drainErr == nil && len(newOutbound) > 0 {
					t.sendMessages(p.MessageID(), newOutbound, sessionID, hexEncryptionKey, localPartyID, parties)
					progress = true
				}
			}
			if allFinished(protocols) {
				break
			}
			if !progress {
				time.Sleep(PollInterval)
			}
		}

		if allFinished(protocols) {
			t.logger.WithFields(logrus.Fields{
				"slot": slot,
			}).Info("all protocols finished, exiting early")
			break
		}

		t.logger.WithFields(logrus.Fields{
			"slot":     slot,
			"finished": countFinished(protocols),
			"total":    len(protocols),
		}).Info("slot complete")
	}
}

func (t *DKLSTssService) sendMessages(
	messageID string,
	messages []OutboundMsg,
	sessionID, hexEncryptionKey, localPartyID string,
	parties []string,
) {
	messenger := relay.NewMessenger(t.cfg.Relay.Server, sessionID, hexEncryptionKey, true, messageID)
	for _, msg := range messages {
		body := base64.StdEncoding.EncodeToString(msg.Body)
		if msg.To == "" {
			for _, peer := range parties {
				if peer == localPartyID {
					continue
				}
				_ = messenger.Send(localPartyID, peer, body)
			}
		} else {
			_ = messenger.Send(localPartyID, msg.To, body)
		}
	}
}

func filterActive(protocols []KeygenProtocol) []KeygenProtocol {
	var active []KeygenProtocol
	for _, p := range protocols {
		if !p.IsFinished() {
			active = append(active, p)
		}
	}
	return active
}

func allFinished(protocols []KeygenProtocol) bool {
	for _, p := range protocols {
		if !p.IsFinished() {
			return false
		}
	}
	return true
}

func countFinished(protocols []KeygenProtocol) int {
	n := 0
	for _, p := range protocols {
		if p.IsFinished() {
			n++
		}
	}
	return n
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
				}
			} else {
				status.Error = "did not complete within slot budget"
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
