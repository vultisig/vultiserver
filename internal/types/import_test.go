package types

import (
	"testing"

	"github.com/google/uuid"
)

func validBatchImportRequest() BatchImportRequest {
	return BatchImportRequest{
		Name:               "test-vault",
		SessionID:          uuid.New().String(),
		HexEncryptionKey:   "aab2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
		LocalPartyId:       "server",
		EncryptionPassword: "password123",
		Email:              "test@example.com",
		LibType:            KeyImport,
		Protocols:          []string{"ecdsa", "eddsa"},
		Chains:             []string{"Solana"},
	}
}

func TestBatchImportRequestValid(t *testing.T) {
	req := validBatchImportRequest()
	err := req.IsValid()
	if err != nil {
		t.Fatalf("expected valid request, got: %v", err)
	}
}

func TestBatchImportRequestMissingName(t *testing.T) {
	req := validBatchImportRequest()
	req.Name = ""
	err := req.IsValid()
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestBatchImportRequestMissingSessionID(t *testing.T) {
	req := validBatchImportRequest()
	req.SessionID = ""
	err := req.IsValid()
	if err == nil {
		t.Fatal("expected error for missing session_id")
	}
}

func TestBatchImportRequestInvalidSessionID(t *testing.T) {
	req := validBatchImportRequest()
	req.SessionID = "not-a-uuid"
	err := req.IsValid()
	if err == nil {
		t.Fatal("expected error for invalid session_id")
	}
}

func TestBatchImportRequestMissingEncryptionKey(t *testing.T) {
	req := validBatchImportRequest()
	req.HexEncryptionKey = ""
	err := req.IsValid()
	if err == nil {
		t.Fatal("expected error for missing hex_encryption_key")
	}
}

func TestBatchImportRequestInvalidEncryptionKey(t *testing.T) {
	req := validBatchImportRequest()
	req.HexEncryptionKey = "not-hex"
	err := req.IsValid()
	if err == nil {
		t.Fatal("expected error for invalid hex_encryption_key")
	}
}

func TestBatchImportRequestMissingPassword(t *testing.T) {
	req := validBatchImportRequest()
	req.EncryptionPassword = ""
	err := req.IsValid()
	if err == nil {
		t.Fatal("expected error for missing encryption_password")
	}
}

func TestBatchImportRequestInvalidLibType(t *testing.T) {
	req := validBatchImportRequest()
	req.LibType = DKLS
	err := req.IsValid()
	if err == nil {
		t.Fatal("expected error for invalid lib_type")
	}
}

func TestBatchImportRequestEmptyProtocols(t *testing.T) {
	req := validBatchImportRequest()
	req.Protocols = nil
	err := req.IsValid()
	if err == nil {
		t.Fatal("expected error for empty protocols")
	}
}

func TestBatchImportRequestUnknownProtocol(t *testing.T) {
	req := validBatchImportRequest()
	req.Protocols = []string{"ecdsa", "eddsa", "unknown"}
	err := req.IsValid()
	if err == nil {
		t.Fatal("expected error for unknown protocol")
	}
}

func TestBatchImportRequestDuplicateProtocol(t *testing.T) {
	req := validBatchImportRequest()
	req.Protocols = []string{"ecdsa", "ecdsa"}
	err := req.IsValid()
	if err == nil {
		t.Fatal("expected error for duplicate protocol")
	}
}

func TestBatchImportRequestNoChains(t *testing.T) {
	req := validBatchImportRequest()
	req.Chains = nil
	err := req.IsValid()
	if err != nil {
		t.Fatalf("chains should be optional, got: %v", err)
	}
}
