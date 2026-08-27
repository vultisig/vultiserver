package common

import "fmt"

// DKLSPartyBlacklistKey returns the redis key used to blacklist a DKLS party for a given vault.
//
// Format (as requested): {publicKeyEcdsa}-party_{partyID}
func DKLSPartyBlacklistKey(publicKeyEcdsa, partyID string) string {
	return fmt.Sprintf("%s-party_%s", publicKeyEcdsa, partyID)
}
