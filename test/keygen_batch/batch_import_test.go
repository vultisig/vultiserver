package keygen_batch_test

import (
	"testing"
	"time"
)

type importProtocolDef struct {
	name      string
	messageID string
	setupKey  string
	isEdDSA   bool
	isChain   bool
	chain     string
}

var eddsaChains = []string{"Solana", "Polkadot", "Sui", "Cardano", "Ton"}

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

func isEdDSAChain(chain string) bool {
	for _, c := range eddsaChains {
		if c == chain {
			return true
		}
	}
	return false
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

func TestBuildImportProtocolListBasic(t *testing.T) {
	defs := buildImportProtocolList([]string{"ecdsa", "eddsa"}, nil)
	if len(defs) != 2 {
		t.Fatalf("expected 2 defs, got %d", len(defs))
	}
	if defs[0].name != "ecdsa" || defs[0].messageID != "p-ecdsa" || defs[0].setupKey != "" || defs[0].isEdDSA {
		t.Fatalf("ecdsa def wrong: %+v", defs[0])
	}
	if defs[1].name != "eddsa" || defs[1].messageID != "p-eddsa" || defs[1].setupKey != "eddsa_key_import" || !defs[1].isEdDSA {
		t.Fatalf("eddsa def wrong: %+v", defs[1])
	}
}

func TestBuildImportProtocolListWithChains(t *testing.T) {
	defs := buildImportProtocolList([]string{"ecdsa", "eddsa"}, []string{"Solana", "Sui"})
	if len(defs) != 4 {
		t.Fatalf("expected 4 defs, got %d", len(defs))
	}

	sol := defs[2]
	if sol.name != "Solana" || sol.messageID != "p-Solana" || sol.setupKey != "Solana" {
		t.Fatalf("Solana def wrong: %+v", sol)
	}
	if !sol.isEdDSA {
		t.Fatal("Solana should be EdDSA")
	}
	if !sol.isChain || sol.chain != "Solana" {
		t.Fatalf("Solana should be marked as chain: %+v", sol)
	}

	sui := defs[3]
	if sui.name != "Sui" || sui.messageID != "p-Sui" || sui.setupKey != "Sui" {
		t.Fatalf("Sui def wrong: %+v", sui)
	}
	if !sui.isEdDSA {
		t.Fatal("Sui should be EdDSA")
	}
}

func TestBuildImportProtocolListEdDSAChainClassification(t *testing.T) {
	tests := []struct {
		chain   string
		isEdDSA bool
	}{
		{"Solana", true},
		{"Polkadot", true},
		{"Sui", true},
		{"Cardano", true},
		{"Ton", true},
		{"Bitcoin", false},
		{"Ethereum", false},
	}
	for _, tt := range tests {
		defs := buildImportProtocolList([]string{"ecdsa"}, []string{tt.chain})
		chainDef := defs[len(defs)-1]
		if chainDef.isEdDSA != tt.isEdDSA {
			t.Errorf("chain %s: isEdDSA = %v, want %v", tt.chain, chainDef.isEdDSA, tt.isEdDSA)
		}
	}
}

func TestAllProtocolsGetUniqueMessageIDs(t *testing.T) {
	defs := buildImportProtocolList(
		[]string{"ecdsa", "eddsa"},
		[]string{"Solana", "Sui", "Ton", "Bitcoin"},
	)

	seen := map[string]bool{}
	for _, d := range defs {
		if seen[d.messageID] {
			t.Fatalf("duplicate messageID: %s", d.messageID)
		}
		seen[d.messageID] = true
	}
}

func TestImportWithMultipleEdDSAChainsRunParallel(t *testing.T) {
	ecdsa := NewMockProtocol("ecdsa", "p-ecdsa", 2, false)
	eddsa := NewMockProtocol("eddsa", "p-eddsa", 2, false)
	solana := NewMockProtocol("Solana", "p-Solana", 2, false)
	sui := NewMockProtocol("Sui", "p-Sui", 2, false)
	ton := NewMockProtocol("Ton", "p-Ton", 2, false)

	protocols := []*MockProtocol{ecdsa, eddsa, solana, sui, ton}
	parties := []string{"server", "client"}

	result := runKeygen(protocols, parties, KeygenTimeout)

	if len(result.errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.errors)
	}
	for _, p := range protocols {
		if !p.IsFinished() {
			t.Fatalf("protocol %s should have finished", p.Name())
		}
	}

	doneCount := 0
	for _, n := range result.notifications {
		if n.Status == StatusDone {
			doneCount++
		}
	}
	if doneCount != 5 {
		t.Fatalf("expected 5 done notifications, got %d", doneCount)
	}
}

func TestImportChainFailureDoesNotBlockOthers(t *testing.T) {
	ecdsa := NewMockProtocol("ecdsa", "p-ecdsa", 2, false)
	eddsa := NewMockProtocol("eddsa", "p-eddsa", 2, false)
	solana := NewMockProtocol("Solana", "p-Solana", 1, true)
	sui := NewMockProtocol("Sui", "p-Sui", 2, false)

	protocols := []*MockProtocol{ecdsa, eddsa, solana, sui}
	parties := []string{"server", "client"}

	result := runKeygen(protocols, parties, KeygenTimeout)

	if !ecdsa.IsFinished() {
		t.Fatal("ecdsa should have finished")
	}
	if !eddsa.IsFinished() {
		t.Fatal("eddsa should have finished")
	}
	if solana.IsFinished() {
		t.Fatal("Solana should NOT have finished (always fails)")
	}
	if !sui.IsFinished() {
		t.Fatal("Sui should have finished despite Solana failure")
	}
	if result.errors["Solana"] == nil {
		t.Fatal("Solana error should have been captured")
	}
}

func TestImportECDSAFailureIsCritical(t *testing.T) {
	ecdsa := NewMockProtocol("ecdsa", "p-ecdsa", 1, true)
	eddsa := NewMockProtocol("eddsa", "p-eddsa", 1, false)
	solana := NewMockProtocol("Solana", "p-Solana", 1, false)

	protocols := []*MockProtocol{ecdsa, eddsa, solana}
	parties := []string{"server", "client"}

	result := runKeygen(protocols, parties, KeygenTimeout)

	if ecdsa.IsFinished() {
		t.Fatal("ecdsa should NOT have finished")
	}
	if result.errors["ecdsa"] == nil {
		t.Fatal("ecdsa failure should have been detected")
	}
}

func TestImportManyChainsConcurrentTiming(t *testing.T) {
	chains := []string{"Solana", "Sui", "Ton", "Polkadot", "Cardano"}
	var protocols []*MockProtocol
	protocols = append(protocols, NewMockProtocol("ecdsa", "p-ecdsa", 1, false))
	protocols = append(protocols, NewMockProtocol("eddsa", "p-eddsa", 1, false))
	for _, chain := range chains {
		protocols = append(protocols, NewMockProtocol(chain, "p-"+chain, 1, false))
	}
	parties := []string{"server", "client"}

	start := time.Now()
	result := runKeygen(protocols, parties, KeygenTimeout)
	elapsed := time.Since(start)

	if len(result.errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.errors)
	}
	for _, p := range protocols {
		if !p.IsFinished() {
			t.Fatalf("protocol %s should have finished", p.Name())
		}
	}
	if elapsed > KeygenTimeout/2 {
		t.Fatalf("7 protocols should finish fast in parallel, took %v", elapsed)
	}
}
