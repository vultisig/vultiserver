package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
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

var requiredProtocols = map[string]bool{
	"ecdsa": true,
	"eddsa": true,
}

func (t *DKLSTssService) ProceeDKLSKeygenParallel(req types.VaultCreateRequest, protocolNames []string) (*KeygenResult, error) {
	err := validateProtocolList(protocolNames)
	if err != nil {
		return nil, err
	}

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
		"sessionID":      req.SessionID,
		"parties_joined": partiesJoined,
		"protocols":      protocolNames,
	}).Info("Parallel keygen session started")

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

	protocols, err := t.initProtocols(protocolNames, setupMsg, req.LocalPartyId, partiesJoined)
	if err != nil {
		return nil, fmt.Errorf("failed to init protocols: %w", err)
	}
	defer freeProtocols(protocols)

	t.runKeygenSlots(protocols, req.SessionID, req.HexEncryptionKey, req.LocalPartyId, partiesJoined)

	for _, p := range protocols {
		if p.Required() && !p.IsFinished() {
			return nil, fmt.Errorf("required protocol %s did not complete", p.Name())
		}
	}

	err = relayClient.CompleteSession(req.SessionID, req.LocalPartyId)
	if err != nil {
		t.logger.WithFields(logrus.Fields{
			"session": req.SessionID,
			"error":   err,
		}).Error("Failed to complete session")
	}

	isCompleted, err := relayClient.CheckCompletedParties(req.SessionID, partiesJoined)
	if err != nil || !isCompleted {
		return nil, fmt.Errorf("failed to check completed parties: %w", err)
	}

	result := t.collectResults(protocols)

	if t.backup != nil {
		err = t.backupFromResult(req, partiesJoined, result)
		if err != nil {
			return result, fmt.Errorf("failed to backup vault: %w", err)
		}
	}

	return result, nil
}

func validateProtocolList(names []string) error {
	hasECDSA := false
	hasEdDSA := false
	for _, name := range names {
		if !knownProtocols[name] {
			return fmt.Errorf("unknown protocol: %s", name)
		}
		if name == "ecdsa" {
			hasECDSA = true
		}
		if name == "eddsa" {
			hasEdDSA = true
		}
	}
	if !hasECDSA {
		return fmt.Errorf("ecdsa is required")
	}
	if !hasEdDSA {
		return fmt.Errorf("eddsa is required")
	}
	return nil
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
	required := requiredProtocols[name]
	switch name {
	case "ecdsa":
		return NewMPCKeygenProtocol("ecdsa", "p-ecdsa", required, setupMsg, localPartyID, false, false)
	case "eddsa":
		return NewMPCKeygenProtocol("eddsa", "p-eddsa", required, setupMsg, localPartyID, true, false)
	case "frozt":
		return NewFroztKeygenProtocol("frozt", "p-frozt", required, localPartyID, parties)
	case "fromt":
		return NewFromtKeygenProtocol("fromt", "p-fromt", required, localPartyID, parties)
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
				messages, err := relayClient.DownloadMessages(sessionID, localPartyID, p.MessageID())
				if err != nil {
					continue
				}
				for _, msg := range messages {
					if msg.From == localPartyID {
						continue
					}
					body, err := t.decodeDecryptMessage(msg.Body, hexEncryptionKey)
					if err != nil {
						t.logger.WithFields(logrus.Fields{
							"protocol": p.Name(),
							"from":     msg.From,
							"error":    err,
						}).Error("decrypt failed")
						_ = relayClient.DeleteMessageFromServer(sessionID, localPartyID, msg.Hash, p.MessageID())
						continue
					}
					finished, err := p.ProcessInbound(msg.From, body)
					if err != nil {
						t.logger.WithFields(logrus.Fields{
							"protocol": p.Name(),
							"from":     msg.From,
							"error":    err,
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
				newOutbound, err := p.DrainOutbound(parties)
				if err == nil && len(newOutbound) > 0 {
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

		finished := countFinished(protocols)
		t.logger.WithFields(logrus.Fields{
			"slot":     slot,
			"finished": finished,
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

func (t *DKLSTssService) collectResults(protocols []KeygenProtocol) *KeygenResult {
	result := &KeygenResult{
		phaseResults: make(map[string]*PhaseResult),
	}
	for _, p := range protocols {
		status := KeygenPhaseStatus{Name: p.Name()}
		if p.IsFinished() {
			phaseResult, err := p.Result()
			if err != nil {
				status.Error = err.Error()
			} else {
				status.Success = true
				status.PublicKey = phaseResult.PublicKey
				result.phaseResults[p.Name()] = phaseResult
				if p.Name() == "ecdsa" {
					result.ECDSAPublicKey = phaseResult.PublicKey
				}
				if p.Name() == "eddsa" {
					result.EDDSAPublicKey = phaseResult.PublicKey
				}
			}
		} else {
			status.Error = "did not complete within slot budget"
		}
		result.Phases = append(result.Phases, status)
	}
	return result
}

func (t *DKLSTssService) backupFromResult(
	req types.VaultCreateRequest,
	partiesJoined []string,
	result *KeygenResult,
) error {
	ecdsaResult := result.phaseResults["ecdsa"]
	eddsaResult := result.phaseResults["eddsa"]
	if ecdsaResult == nil || eddsaResult == nil {
		return fmt.Errorf("ecdsa and eddsa results are required for backup")
	}

	vault := &vaultType.Vault{
		Name:           req.Name,
		PublicKeyEcdsa: ecdsaResult.PublicKey,
		PublicKeyEddsa: eddsaResult.PublicKey,
		Signers:        partiesJoined,
		CreatedAt:      timestamppb.New(time.Now()),
		HexChainCode:   ecdsaResult.ChainCode,
		KeyShares: []*vaultType.Vault_KeyShare{
			{PublicKey: ecdsaResult.PublicKey, Keyshare: ecdsaResult.Keyshare},
			{PublicKey: eddsaResult.PublicKey, Keyshare: eddsaResult.Keyshare},
		},
		LocalPartyId:  req.LocalPartyId,
		ResharePrefix: "",
	}

	switch req.LibType {
	case types.DKLS:
		vault.LibType = keygen.LibType_LIB_TYPE_DKLS
	case types.GG20:
		vault.LibType = keygen.LibType_LIB_TYPE_GG20
	default:
		vault.LibType = keygen.LibType_LIB_TYPE_DKLS
	}

	froztPhase := result.phaseResults["frozt"]
	if froztPhase != nil {
		vault.ChainPublicKeys = append(vault.ChainPublicKeys,
			&vaultType.Vault_ChainPublicKey{Chain: "ZcashSapling", PublicKey: froztPhase.PublicKey},
		)
		vault.KeyShares = append(vault.KeyShares,
			&vaultType.Vault_KeyShare{PublicKey: froztPhase.PublicKey, Keyshare: froztPhase.Keyshare},
		)
	}

	fromtPhase := result.phaseResults["fromt"]
	if fromtPhase != nil {
		vault.ChainPublicKeys = append(vault.ChainPublicKeys,
			&vaultType.Vault_ChainPublicKey{Chain: "Monero", PublicKey: fromtPhase.PublicKey},
		)
		vault.KeyShares = append(vault.KeyShares,
			&vaultType.Vault_KeyShare{PublicKey: fromtPhase.PublicKey, Keyshare: fromtPhase.Keyshare},
		)
	}

	return t.backup.SaveVaultAndScheduleEmail(vault, req.EncryptionPassword, req.Email)
}
