package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	frozt "github.com/vultisig/frost-zm/go/frozt"
	mldsaSession "github.com/vultisig/go-wrappers/mldsa"

	"github.com/vultisig/vultiserver/service"
)

func main() {
	relayURL := envOrDefault("RELAY_URL", "http://relay:8080")
	server1URL := envOrDefault("SERVER1_URL", "http://vultiserver1:8080")
	server2URL := envOrDefault("SERVER2_URL", "http://vultiserver2:8080")

	fmt.Println("=== Parallel Keygen Integration Test ===")
	fmt.Printf("Relay: %s\n", relayURL)
	fmt.Printf("Server1: %s\n", server1URL)
	fmt.Printf("Server2: %s\n", server2URL)

	waitForHealth(relayURL+"/ping", 30*time.Second)
	waitForHealth(server1URL+"/ping", 30*time.Second)
	waitForHealth(server2URL+"/ping", 30*time.Second)
	fmt.Println("All services healthy")

	sessionID := uuid.New().String()
	hexEncryptionKey := randomHex(32)
	party1 := "server-party-1"
	party2 := "server-party-2"
	parties := []string{party1, party2}

	fmt.Printf("Session: %s\n", sessionID)
	fmt.Printf("Parties: %v\n", parties)

	wrapper := service.NewMPCWrapperImp(false, false)
	keyID := randomBytes(32)
	idsBytes := encodePartyIDs(parties)
	setupMsg, err := wrapper.KeygenSetupMsgNew(mldsaSession.MlDsa44, len(parties), keyID, idsBytes)
	if err != nil {
		fatal("KeygenSetupMsgNew: %v", err)
	}
	fmt.Printf("Setup message created: %d bytes\n", len(setupMsg))

	encryptedSetup := encryptAndEncode(setupMsg, hexEncryptionKey)

	protocols := []string{"ecdsa", "eddsa", "frozt", "fromt"}

	go postParallelKeygen(server1URL, sessionID, hexEncryptionKey, party1, protocols)
	go postParallelKeygen(server2URL, sessionID, hexEncryptionKey, party2, protocols)
	fmt.Println("POSTed to both servers, waiting for workers to register...")

	waitForParties(relayURL, sessionID, len(parties), 60*time.Second)
	fmt.Println("All parties registered")

	uploadSetupMessage(relayURL, sessionID, encryptedSetup)
	fmt.Println("Setup message uploaded to relay")

	startSession(relayURL, sessionID, parties)
	fmt.Println("Session started")

	sendFroztMetadata(relayURL, sessionID, hexEncryptionKey, parties)
	sendFromtMetadata(relayURL, sessionID, hexEncryptionKey, parties)
	fmt.Println("Metadata sent for frozt + fromt")

	fmt.Println("Waiting for keygen to complete...")
	time.Sleep(30 * time.Second)

	fmt.Println("=== Integration test completed ===")
	fmt.Println("Check vultiserver logs for keygen results")
	os.Exit(0)
}

func envOrDefault(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func encodePartyIDs(parties []string) []byte {
	return []byte(strings.Join(parties, "\x00"))
}

func encryptGCM(plainText, hexKey string) (string, error) {
	passwd, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(passwd)
	key := hash[:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return string(ciphertext), nil
}

func encryptAndEncode(data []byte, hexKey string) string {
	innerBase64 := base64.StdEncoding.EncodeToString(data)
	encrypted, err := encryptGCM(innerBase64, hexKey)
	if err != nil {
		fatal("encrypt: %v", err)
	}
	return base64.StdEncoding.EncodeToString([]byte(encrypted))
}

func uploadSetupMessage(relayURL, sessionID, payload string) {
	url := relayURL + "/setup-message/" + sessionID
	req, _ := http.NewRequest("POST", url, strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fatal("upload setup: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		fatal("upload setup: status %d: %s", resp.StatusCode, body)
	}
}

func registerParty(relayURL, sessionID, partyID string) {
	url := relayURL + "/" + sessionID
	body := []byte(`["` + partyID + `"]`)
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		fatal("register: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		fatal("register %s: status %d: %s", partyID, resp.StatusCode, respBody)
	}
}

func startSession(relayURL, sessionID string, parties []string) {
	url := relayURL + "/start/" + sessionID
	body, _ := json.Marshal(parties)
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		fatal("start session: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		fatal("start session: status %d: %s", resp.StatusCode, respBody)
	}
}

func postParallelKeygen(serverURL, sessionID, hexEncryptionKey, localPartyID string, protocols []string) {
	reqBody := map[string]interface{}{
		"name":                "integration-test-vault",
		"session_id":          sessionID,
		"hex_encryption_key":  hexEncryptionKey,
		"hex_chain_code":      randomHex(32),
		"local_party_id":      localPartyID,
		"encryption_password": "test-password-123",
		"email":               "test@test.com",
		"lib_type":            1,
		"protocols":           protocols,
	}
	body, _ := json.Marshal(reqBody)
	resp, err := http.Post(serverURL+"/vault/batch", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("POST to %s failed: %v\n", serverURL, err)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	fmt.Printf("POST %s/vault/batch → %d %s\n", serverURL, resp.StatusCode, string(respBody))
}

func sendFroztMetadata(relayURL, sessionID, hexEncryptionKey string, parties []string) {
	_, metadataBytes, err := frozt.KeygenMetadataCreate(0)
	if err != nil {
		fmt.Printf("WARNING: frozt.KeygenMetadataCreate failed: %v\n", err)
		return
	}
	fmt.Printf("Frozt metadata: %d bytes\n", len(metadataBytes))

	for _, party := range parties {
		sendRelayMessage(relayURL, sessionID, hexEncryptionKey, "coordinator", party, metadataBytes, "p-frozt-metadata")
	}

	metadataHash, err := frozt.KeygenMetadataHash(metadataBytes)
	if err != nil {
		fmt.Printf("WARNING: frozt.KeygenMetadataHash failed: %v\n", err)
		return
	}

	time.Sleep(500 * time.Millisecond)

	for _, party := range parties {
		sendRelayMessage(relayURL, sessionID, hexEncryptionKey, "coordinator", party, metadataHash, "p-frozt-metadata-hash")
	}
}

func sendFromtMetadata(relayURL, sessionID, hexEncryptionKey string, parties []string) {
	metaBytes := make([]byte, 9)
	metaBytes[0] = 1
	binary.LittleEndian.PutUint64(metaBytes[1:], 0)

	for _, party := range parties {
		sendRelayMessage(relayURL, sessionID, hexEncryptionKey, "coordinator", party, metaBytes, "p-fromt-metadata")
	}
}

func sendRelayMessage(relayURL, sessionID, hexEncryptionKey, from, to string, data []byte, messageID string) {
	innerBase64 := base64.StdEncoding.EncodeToString(data)
	encrypted, err := encryptGCM(innerBase64, hexEncryptionKey)
	if err != nil {
		fmt.Printf("WARNING: encrypt failed: %v\n", err)
		return
	}
	body := base64.StdEncoding.EncodeToString([]byte(encrypted))

	hash := md5.Sum([]byte(body))
	hashStr := hex.EncodeToString(hash[:])

	msg := struct {
		SessionID string   `json:"session_id"`
		From      string   `json:"from"`
		To        []string `json:"to"`
		Body      string   `json:"body"`
		Hash      string   `json:"hash"`
	}{
		SessionID: sessionID,
		From:      from,
		To:        []string{to},
		Body:      body,
		Hash:      hashStr,
	}

	buf, _ := json.Marshal(msg)
	url := relayURL + "/message/" + sessionID
	req, _ := http.NewRequest("POST", url, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	if messageID != "" {
		req.Header.Set("message_id", messageID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("WARNING: send relay message failed: %v\n", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		respBody, _ := io.ReadAll(resp.Body)
		fmt.Printf("WARNING: relay message status %d: %s\n", resp.StatusCode, respBody)
	}
}

func waitForParties(relayURL, sessionID string, expected int, timeout time.Duration) {
	url := relayURL + "/" + sessionID
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			time.Sleep(time.Second)
			continue
		}
		var parties []string
		_ = json.Unmarshal(body, &parties)
		fmt.Printf("  Parties registered: %d/%d %v\n", len(parties), expected, parties)
		if len(parties) >= expected {
			return
		}
		time.Sleep(time.Second)
	}
	fatal("timeout waiting for %d parties to register", expected)
}

func waitForHealth(url string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(time.Second)
	}
	fatal("timeout waiting for %s", url)
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
	os.Exit(1)
}
