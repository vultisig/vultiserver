package types

import "testing"

func validKeysignRequest() KeysignRequest {
	return KeysignRequest{
		PublicKey:        "02aabbcc",
		Messages:         []string{"deadbeef"},
		SessionID:        "some-session-id",
		HexEncryptionKey: "aab2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
		DerivePath:       "m/44'/0'/0'/0/0",
	}
}

func TestKeysignRequestValid(t *testing.T) {
	req := validKeysignRequest()
	if err := req.IsValid(); err != nil {
		t.Fatalf("expected valid request, got: %v", err)
	}
}

func TestKeysignRequestEmptySession(t *testing.T) {
	req := validKeysignRequest()
	req.SessionID = ""
	if err := req.IsValid(); err == nil {
		t.Fatal("expected error for empty session id")
	}
}
