package service

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
	"google.golang.org/protobuf/types/known/timestamppb"

	keygen "github.com/vultisig/commondata/go/vultisig/keygen/v1"
	vaultType "github.com/vultisig/commondata/go/vultisig/vault/v1"

	"github.com/vultisig/vultiserver/internal/types"
	"github.com/vultisig/vultiserver/relay"
)

func (t *DKLSTssService) ProcessBatchImport(req types.BatchImportRequest) (*KeygenResult, error) {
	if !types.ContainsProtocol(req.Protocols, "ecdsa") {
		return nil, fmt.Errorf("ecdsa is required for import")
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
		"sessionID": req.SessionID,
		"parties":   partiesJoined,
		"protocols": req.Protocols,
		"chains":    req.Chains,
	}).Info("Batch import session started")

	allProtocols := buildImportProtocolList(req.Protocols, req.Chains)

	protocols, err := t.initImportProtocols(allProtocols, relayClient, req.SessionID, req.HexEncryptionKey, req.LocalPartyId)
	if err != nil {
		return nil, fmt.Errorf("failed to init import protocols: %w", err)
	}
	defer freeProtocols(protocols)

	t.runKeygen(protocols, req.SessionID, req.HexEncryptionKey, req.LocalPartyId, partiesJoined)

	for _, p := range protocols {
		if !p.IsFinished() {
			return nil, fmt.Errorf("%s import failed — cannot create vault", p.Name())
		}
	}

	allNames := make([]string, 0, len(allProtocols))
	for _, ip := range allProtocols {
		allNames = append(allNames, ip.name)
	}
	result := t.collectResults(protocols, allNames, allNames)

	if !hasAnySuccess(result) {
		return result, fmt.Errorf("all import protocols failed")
	}

	if t.backup != nil {
		backupErr := t.saveImportedVault(req, partiesJoined, result)
		if backupErr != nil {
			return nil, fmt.Errorf("failed to store imported vault: %w", backupErr)
		}
	}

	completeErr := relayClient.CompleteSession(req.SessionID, req.LocalPartyId)
	if completeErr != nil {
		t.logger.WithField("error", completeErr).Warn("failed to complete session")
	}

	return result, nil
}

type importProtocolDef struct {
	name      string
	messageID string
	setupKey  string
	isEdDSA   bool
	isChain   bool
	chain     string
}

type storedImportChain struct {
	resultKey string
	chain     string
	isEdDSA   bool
}

var importChainGroups = map[string][]string{
	"ETH": {
		"Ethereum",
		"Arbitrum",
		"Avalanche",
		"Base",
		"Blast",
		"BSC",
		"CronosChain",
		"Optimism",
		"Polygon",
		"Zksync",
		"Mantle",
		"Hyperliquid",
		"Sei",
	},
	"ATOM": {
		"Cosmos",
		"Osmosis",
		"Kujira",
		"Dydx",
		"Noble",
		"Akash",
	},
	"RUNE": {
		"THORChain",
		"MayaChain",
	},
	"LUNA": {
		"Terra",
		"TerraClassic",
	},
}

func importSetupKey(name string) string {
	switch name {
	case "ecdsa":
		return ""
	case "eddsa":
		return "eddsa_key_import"
	default:
		return name
	}
}

func buildImportProtocolList(protocols []string, chains []string) []importProtocolDef {
	var defs []importProtocolDef
	for _, p := range protocols {
		isEdDSA := p == "eddsa"
		defs = append(defs, importProtocolDef{
			name:      p,
			messageID: "p-" + p,
			setupKey:  importSetupKey(p),
			isEdDSA:   isEdDSA,
		})
	}
	for _, chain := range chains {
		isEdDSA := isEdDSAChain(chain)
		defs = append(defs, importProtocolDef{
			name:      chain,
			messageID: "p-" + chain,
			setupKey:  chain,
			isEdDSA:   isEdDSA,
			isChain:   true,
			chain:     chain,
		})
	}
	return defs
}

func expandStoredImportChains(chains []string) []storedImportChain {
	var result []storedImportChain

	for _, chain := range chains {
		expandedChains, ok := importChainGroups[chain]
		if !ok {
			expandedChains = []string{chain}
		}

		for _, expandedChain := range expandedChains {
			result = append(result, storedImportChain{
				resultKey: chain,
				chain:     expandedChain,
				isEdDSA:   isEdDSAChain(expandedChain),
			})
		}
	}

	return result
}

func isEdDSAChain(chain string) bool {
	return slices.Contains(EddsaChains, chain)
}

func (t *DKLSTssService) initImportProtocols(
	defs []importProtocolDef,
	relayClient *relay.Client,
	sessionID, hexEncryptionKey, localPartyID string,
) ([]KeygenProtocol, error) {
	var protocols []KeygenProtocol
	for _, def := range defs {
		setupMsg, err := t.fetchProtocolSetupMessage(relayClient, sessionID, hexEncryptionKey, def.setupKey)
		if err != nil {
			freeProtocols(protocols)
			return nil, fmt.Errorf("setup for %s: %w", def.name, err)
		}
		t.logger.WithFields(logrus.Fields{
			"protocol":   def.name,
			"setupLen":   len(setupMsg),
			"localParty": localPartyID,
		}).Info("setup message decoded for protocol")
		p, err := t.initImportProtocol(def, setupMsg, localPartyID)
		if err != nil {
			freeProtocols(protocols)
			return nil, fmt.Errorf("init import %s: %w", def.name, err)
		}
		protocols = append(protocols, p)
	}
	return protocols, nil
}

func (t *DKLSTssService) initImportProtocol(def importProtocolDef, setupMsg []byte, localPartyID string) (KeygenProtocol, error) {
	switch def.name {
	case "frozt":
		return NewFroztImportProtocol(def.name, def.messageID, setupMsg, localPartyID)
	case "fromt":
		return NewFromtImportProtocol(def.name, def.messageID, setupMsg, localPartyID)
	default:
		return NewMPCImportProtocol(def.name, def.messageID, setupMsg, localPartyID, def.isEdDSA)
	}
}

func (t *DKLSTssService) saveImportedVault(
	req types.BatchImportRequest,
	partiesJoined []string,
	result *KeygenResult,
) error {
	ecdsaResult := result.phaseResults["ecdsa"]
	if ecdsaResult == nil {
		return fmt.Errorf("ecdsa result required for import vault")
	}

	vault := &vaultType.Vault{
		Name:           req.Name,
		PublicKeyEcdsa: ecdsaResult.PublicKey,
		Signers:        partiesJoined,
		CreatedAt:      timestamppb.New(time.Now()),
		HexChainCode:   ecdsaResult.ChainCode,
		LocalPartyId:   req.LocalPartyId,
		ResharePrefix:  "",
	}

	vault.LibType = keygen.LibType_LIB_TYPE_KEYIMPORT

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

	for _, def := range expandStoredImportChains(req.Chains) {
		pr := result.phaseResults[def.resultKey]
		if pr == nil {
			continue
		}
		upsertChainPublicKey(vault, def.chain, pr.PublicKey, def.isEdDSA)
	}

	return t.backup.SaveVaultAndScheduleEmail(vault, req.EncryptionPassword, req.Email)
}
