package service

import (
	"encoding/base64"
	"fmt"

	vaultType "github.com/vultisig/commondata/go/vultisig/vault/v1"
	frozt "github.com/vultisig/frost-zm/go/frozt"
)

const saplingExtrasChain = "SaplingExtras"

func upsertChainPublicKey(
	vault *vaultType.Vault,
	chain string,
	publicKey string,
	isEddsa bool,
) {
	for _, entry := range vault.ChainPublicKeys {
		if entry.Chain != chain {
			continue
		}

		entry.PublicKey = publicKey
		entry.IsEddsa = isEddsa
		return
	}

	vault.ChainPublicKeys = append(vault.ChainPublicKeys, &vaultType.Vault_ChainPublicKey{
		Chain:     chain,
		PublicKey: publicKey,
		IsEddsa:   isEddsa,
	})
}

func setFroztVaultEntries(
	vault *vaultType.Vault,
	publicKey string,
	keyshare string,
) error {
	upsertChainPublicKey(vault, "ZcashSapling", publicKey, false)

	bundle, err := base64.StdEncoding.DecodeString(keyshare)
	if err != nil {
		return fmt.Errorf("decode frozt keyshare: %w", err)
	}

	saplingExtras, err := frozt.KeyShareBundleSaplingExtras(bundle)
	if err != nil {
		return fmt.Errorf("extract frozt sapling extras: %w", err)
	}

	upsertChainPublicKey(
		vault,
		saplingExtrasChain,
		base64.StdEncoding.EncodeToString(saplingExtras),
		false,
	)

	return nil
}

func setFromtVaultEntries(vault *vaultType.Vault, publicKey string) {
	upsertChainPublicKey(vault, "Monero", publicKey, false)
}
