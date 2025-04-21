package keygen_test

// import (
// 	"bytes"
// 	"encoding/json"
// 	"fmt"
// 	"io"
// 	"net/http"
// 	"os"
// 	"sync"
// 	"testing"
// 	"time"

// 	"github.com/vultisig/mobile-tss-lib/coordinator"
// 	"github.com/vultisig/vultiserver/relay"
// )

// type VaultCreateResponse struct {
// 	Name             string `json:"name"`
// 	SessionID        string `json:"session_id"`
// 	HexEncryptionKey string `json:"hex_encryption_key"`
// 	HexChainCode     string `json:"hex_chain_code"`
// }

// func TestExecuteKeyGeneration(t *testing.T) {
// 	t.Parallel()
// 	t.Logf("Starting key generation test")
// 	// if err := coordinator.CleanTestingKeys(); err != nil {
// 	// 	t.Errorf("Failed to clean up the keys folder: %q", err)
// 	// }

// 	vaultCreateURL := "http://localhost:8181/vault/create"
// 	payload := []byte(`{"name": "test", "encryption_password": "abc"}`)
// 	req, err := http.NewRequest("POST", vaultCreateURL, bytes.NewBuffer(payload))
// 	if err != nil {
// 		t.Fatalf("Failed to create request: %q", err)
// 	}
// 	req.Header.Set("Content-Type", "application/json")
// 	req.Header.Set("Authorization", "Basic dGVzdDoxMjM=") // test:123, you will have to add this user to your Redis instance

// 	client := &http.Client{Timeout: 10 * time.Second}
// 	resp, err := client.Do(req)
// 	if err != nil {
// 		t.Fatalf("Failed to perform HTTP request: %q", err)
// 	}
// 	defer resp.Body.Close()

// 	if resp.StatusCode != http.StatusOK {
// 		body, _ := io.ReadAll(resp.Body)
// 		t.Fatalf("Received non-OK response: %d, %s", resp.StatusCode, body)
// 	}

// 	t.Logf("Requested Vault creation successfully")

// 	body, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		t.Fatalf("Failed to read response body: %q", err)
// 	}

// 	var vaultResponse VaultCreateResponse
// 	if err := json.Unmarshal(body, &vaultResponse); err != nil {
// 		t.Fatalf("Failed to unmarshal response: %q", err)
// 	}

// 	t.Logf("Vault created successfully: %v\n", vaultResponse)

// 	var wg sync.WaitGroup
// 	parties := []string{"iPhone", "iPad"}
// 	server := "http://127.0.0.1:8080"

// 	paramsMap := map[string]coordinator.KeygenInput{
// 		"iPhone": {
// 			Server:    server,
// 			Session:   vaultResponse.SessionID,
// 			ChainCode: vaultResponse.HexChainCode,
// 			localPartyID:       "iPhone",
// 			KeyFolder: "../keys/IPhone",
// 		},
// 		"iPad": {
// 			Server:    server,
// 			Session:   vaultResponse.SessionID,
// 			ChainCode: vaultResponse.HexChainCode,
// 			localPartyID:       "iPad",
// 			KeyFolder: "../keys/IPad",
// 		},
// 	}

// 	for _, party := range parties {
// 		t.Log("Starting party", party)
// 		partyConfig := paramsMap[party]
// 		wg.Add(1)
// 		go func(partyConfig coordinator.KeygenInput) {
// 			defer wg.Done()
// 			fmt.Println("Joining gen party as", partyConfig.localPartyID)

// 			publicKey, err := coordinator.ExecuteKeyGeneration(partyConfig)
// 			if err != nil {
// 				t.Errorf("Execution for %s failed with %q", partyConfig.localPartyID, err)
// 			}
// 			os.Setenv("PUBLIC_KEY", publicKey)
// 		}(partyConfig)
// 	}

// 	time.Sleep(3 * time.Second)

// 	relayServer := relay.NewServer(server)

// 	partiesInSession, err := relayServer.GetSession(vaultResponse.SessionID)
// 	if err != nil {
// 		t.Fatalf("Failed to start session: %q", err)
// 	}
// 	if len(partiesInSession) < 3 {
// 		t.Fatalf("Expected 3 parties to join, got %d", len(partiesInSession))
// 	}

// 	// Wait 3 seconds to start to simulate someone not instantly pressing the button
// 	fmt.Println("Waiting 3 seconds to start the session")
// 	time.Sleep(3 * time.Second)
// 	fmt.Println("Starting the session")

// 	// We start the session (one of the devices will do this in real life)
// 	err = relayServer.StartSession(vaultResponse.SessionID, partiesInSession)
// 	if err != nil {
// 		t.Fatalf("Failed to start session: %q", err)
// 	}
// 	// expectedParties = []string{"iPhone", "iPad", "Vultisigner"}

// 	wg.Wait()
// }
