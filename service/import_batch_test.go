package service

import "testing"

func TestExpandStoredImportChains(t *testing.T) {
	defs := expandStoredImportChains([]string{"ETH", "ATOM", "Solana", "RUNE", "LUNA"})

	expected := map[string]string{
		"Ethereum":     "ETH",
		"Arbitrum":     "ETH",
		"Avalanche":    "ETH",
		"Base":         "ETH",
		"Blast":        "ETH",
		"BSC":          "ETH",
		"CronosChain":  "ETH",
		"Optimism":     "ETH",
		"Polygon":      "ETH",
		"Zksync":       "ETH",
		"Mantle":       "ETH",
		"Hyperliquid":  "ETH",
		"Sei":          "ETH",
		"Cosmos":       "ATOM",
		"Osmosis":      "ATOM",
		"Kujira":       "ATOM",
		"Dydx":         "ATOM",
		"Noble":        "ATOM",
		"Akash":        "ATOM",
		"Solana":       "Solana",
		"THORChain":    "RUNE",
		"MayaChain":    "RUNE",
		"Terra":        "LUNA",
		"TerraClassic": "LUNA",
	}

	if len(defs) != len(expected) {
		t.Fatalf("expected %d stored chains, got %d", len(expected), len(defs))
	}

	for _, def := range defs {
		resultKey, ok := expected[def.chain]
		if !ok {
			t.Fatalf("unexpected stored chain: %+v", def)
		}
		if def.resultKey != resultKey {
			t.Fatalf("chain %s stored from %s, want %s", def.chain, def.resultKey, resultKey)
		}
		if def.chain == "Solana" && !def.isEdDSA {
			t.Fatal("Solana should be marked as EdDSA")
		}
		if def.chain == "Ethereum" && def.isEdDSA {
			t.Fatal("Ethereum should not be marked as EdDSA")
		}
	}
}
