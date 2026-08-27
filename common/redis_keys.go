package common

// DKLSVaultBlacklistKey returns the redis key used to blacklist a vault for DKLS keysign.
//
// Per current server constraints (2/2 vault), blacklisting a single party effectively means
// blacklisting the whole vault.
//
// Format (as requested): {publicKeyEcdsa}
func DKLSVaultBlacklistKey(publicKeyEcdsa string) string {
	return publicKeyEcdsa
}
