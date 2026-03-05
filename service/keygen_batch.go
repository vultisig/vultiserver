package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
		if vaultHasProtocol(vault, name) {
			continue
		}
		needed = append(needed, name)
	}
	return needed
}

func vaultHasProtocol(vault *vaultType.Vault, name string) bool {
	return protocolPublicKey(vault, name) != ""
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
	relayClient := relay.NewRelayClient(t.cfg.Relay.Server)
	deadline := time.Now().Add(KeygenTimeout)
	failedNotified := make(map[string]bool)

	for _, p := range protocols {
		outbound, err := p.DrainOutbound(parties)
		if len(outbound) > 0 {
			sendErr := t.sendMessages(p.MessageID(), outbound, sessionID, hexEncryptionKey, localPartyID, parties)
			if sendErr != nil {
				t.logger.WithFields(logrus.Fields{
					"protocol": p.Name(),
					"error":    sendErr,
				}).Warn("initial send outbound failed")
			}
		}
		if err != nil {
			t.logger.WithFields(logrus.Fields{
				"protocol": p.Name(),
				"error":    err,
			}).Error("initial drain outbound failed")
		}
	}

	for time.Now().Before(deadline) {
		if allFinished(protocols) {
			t.logger.Info("all protocols finished")
			return
		}

		progress := false
		for _, p := range protocols {
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
					if !failedNotified[p.Name()] {
						t.notifyStatus(sessionID, hexEncryptionKey, localPartyID, parties, p.Name(), StatusFailed, procErr.Error(), "")
						failedNotified[p.Name()] = true
					}
				}
				_ = relayClient.DeleteMessageFromServer(sessionID, localPartyID, msg.Hash, p.MessageID())
				progress = true
				if finished {
					publicKey := ""
					pr, resultErr := p.Result()
					if resultErr == nil {
						publicKey = pr.PublicKey
					}
					t.logger.WithFields(logrus.Fields{
						"protocol":  p.Name(),
						"publicKey": publicKey,
					}).Info("protocol finished")
					t.notifyStatus(sessionID, hexEncryptionKey, localPartyID, parties, p.Name(), StatusDone, "", publicKey)
					break
				}
			}
			newOutbound, drainErr := p.DrainOutbound(parties)
			if len(newOutbound) > 0 {
				sendErr := t.sendMessages(p.MessageID(), newOutbound, sessionID, hexEncryptionKey, localPartyID, parties)
				if sendErr != nil {
					t.logger.WithFields(logrus.Fields{"protocol": p.Name(), "error": sendErr}).Warn("send outbound failed")
				} else {
					progress = true
				}
			}
			if drainErr != nil {
				t.logger.WithFields(logrus.Fields{"protocol": p.Name(), "error": drainErr}).Warn("drain outbound failed")
			}
		}

		if !progress {
			time.Sleep(PollInterval)
		}
	}

	for _, p := range protocols {
		if !p.IsFinished() && !failedNotified[p.Name()] {
			t.notifyStatus(sessionID, hexEncryptionKey, localPartyID, parties, p.Name(), StatusTimeout, "", "")
		}
	}
}

func (t *DKLSTssService) sendMessages(
	messageID string,
	messages []OutboundMsg,
	sessionID, hexEncryptionKey, localPartyID string,
	parties []string,
) error {
	messenger := relay.NewMessenger(t.cfg.Relay.Server, sessionID, hexEncryptionKey, true, messageID)
	for _, msg := range messages {
		body := base64.StdEncoding.EncodeToString(msg.Body)
		if msg.To == "" {
			for _, peer := range parties {
				if peer == localPartyID {
					continue
				}
				err := messenger.Send(localPartyID, peer, body)
				if err != nil {
					return fmt.Errorf("send to %s: %w", peer, err)
				}
			}
		} else {
			err := messenger.Send(localPartyID, msg.To, body)
			if err != nil {
				return fmt.Errorf("send to %s: %w", msg.To, err)
			}
		}
	}
	return nil
}

func (t *DKLSTssService) notifyStatus(
	sessionID, hexEncryptionKey, localPartyID string,
	parties []string, protocol, status, errMsg, publicKey string,
) {
	msg := ProtocolStatus{
		Protocol:  protocol,
		Status:    status,
		Error:     errMsg,
		PublicKey: publicKey,
	}
	body, err := json.Marshal(msg)
	if err != nil {
		t.logger.WithFields(logrus.Fields{"protocol": protocol, "error": err}).Warn("failed to marshal status")
		return
	}
	sendErr := t.sendMessages(StatusMessageID, []OutboundMsg{{Body: body}}, sessionID, hexEncryptionKey, localPartyID, parties)
	if sendErr != nil {
		t.logger.WithFields(logrus.Fields{"protocol": protocol, "status": status, "error": sendErr}).Warn("failed to send status notification")
	}
}

func allFinished(protocols []KeygenProtocol) bool {
	for _, p := range protocols {
		if !p.IsFinished() {
			return false
		}
	}
	return true
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
