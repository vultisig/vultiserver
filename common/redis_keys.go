package common

// DKLSVaultBlacklistKey returns the redis key used to blacklist a vault for DKLS keysign.
//
// Per current server constraints (2/2 vault), blacklisting a single party effectively means
// blacklisting the whole vault.
//
// Namespaced so it can never collide with session keys, which are stored under their raw
// (client-supplied) value elsewhere in the server.
func DKLSVaultBlacklistKey(publicKeyEcdsa string) string {
	return "dkls:vault:blacklist:" + publicKeyEcdsa
}
