package common

import "strings"

// dklsVaultBlacklistPrefix namespaces the DKLS vault blacklist key so it can never
// collide with session keys, which are stored under their raw (client-supplied) value
// elsewhere in the server.
const dklsVaultBlacklistPrefix = "dkls:vault:blacklist:"

// reservedRedisKeyPrefixes lists every prefix this server uses to build a "special"
// redis key (as opposed to a raw, client-supplied session id). A client-supplied
// session id must never be allowed to start with one of these, otherwise it could be
// crafted to collide with one of those keys in the shared redis keyspace.
var reservedRedisKeyPrefixes = []string{
	dklsVaultBlacklistPrefix,
	"resend_",
	"verification_code_",
}

// DKLSVaultBlacklistKey returns the redis key used to blacklist a vault for DKLS keysign.
//
// Per current server constraints (2/2 vault), blacklisting a single party effectively means
// blacklisting the whole vault.
func DKLSVaultBlacklistKey(publicKeyEcdsa string) string {
	return dklsVaultBlacklistPrefix + publicKeyEcdsa
}

// IsReservedRedisKeyPrefix reports whether key starts with a prefix reserved for a
// non-session redis key elsewhere in this server.
func IsReservedRedisKeyPrefix(key string) bool {
	for _, prefix := range reservedRedisKeyPrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}
