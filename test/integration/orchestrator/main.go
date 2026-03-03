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

var (
	relayURL   string
	server1URL string
	server2URL string
	party1     = "server-party-1"
	party2     = "server-party-2"
	parties    = []string{party1, party2}
)

func main() {
	relayURL = envOrDefault("RELAY_URL", "http://relay:8080")
	server1URL = envOrDefault("SERVER1_URL", "http://vultiserver1:8080")
	server2URL = envOrDefault("SERVER2_URL", "http://vultiserver2:8080")

	fmt.Println("=== Batch Keygen Integration Tests ===")
	waitForHealth(relayURL+"/ping", 30*time.Second)
	waitForHealth(server1URL+"/ping", 30*time.Second)
	waitForHealth(server2URL+"/ping", 30*time.Second)
	fmt.Println("All services healthy\n")

	passed := 0
	failed := 0

	if runTest("Test 1: ECDSA+EDDSA full fail (bad setup)", test1_FullFail) {
		passed++
	} else {
		failed++
	}

	ecdsaPK := ""
	if runTestWithResult("Test 2: ECDSA+EDDSA+FROZT partial (frozt fails)", func() (string, bool) {
		return test2_PartialSuccess()
	}, &ecdsaPK) {
		passed++
	} else {
		failed++
	}

	if runTest("Test 3: Append FROZT+FROMT to Test 2 vault", func() bool {
		return test3_Append(ecdsaPK)
	}) {
		passed++
	} else {
		failed++
	}

	if runTest("Test 4: Idempotent — ECDSA already done", func() bool {
		return test4_Idempotent(ecdsaPK)
	}) {
		passed++
	} else {
		failed++
	}

	if runTest("Test 5: Full batch — all 4 succeed", test5_FullBatch) {
		passed++
	} else {
		failed++
	}

	fmt.Printf("\n=== Results: %d passed, %d failed ===\n", passed, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

func runTest(name string, fn func() bool) bool {
	fmt.Printf("--- %s ---\n", name)
	ok := fn()
	if ok {
		fmt.Printf("--- PASS: %s ---\n\n", name)
	} else {
		fmt.Printf("--- FAIL: %s ---\n\n", name)
	}
	return ok
}

func runTestWithResult(name string, fn func() (string, bool), result *string) bool {
	fmt.Printf("--- %s ---\n", name)
	r, ok := fn()
	*result = r
	if ok {
		fmt.Printf("--- PASS: %s ---\n\n", name)
	} else {
		fmt.Printf("--- FAIL: %s ---\n\n", name)
	}
	return ok
}

func test1_FullFail() bool {
	sessionID := uuid.New().String()
	hexKey := randomHex(32)

	badSetup := []byte("this is not a valid setup message")
	encSetup := encryptAndEncode(badSetup, hexKey)

	taskID1 := postBatch(server1URL, sessionID, hexKey, party1, []string{"ecdsa", "eddsa"}, "")
	taskID2 := postBatch(server2URL, sessionID, hexKey, party2, []string{"ecdsa", "eddsa"}, "")
	waitForParties(relayURL, sessionID, 2, 30*time.Second)
	uploadSetupMessage(relayURL, sessionID, encSetup)
	startSession(relayURL, sessionID, parties)

	time.Sleep(15 * time.Second)

	r1 := pollTaskResult(server1URL, taskID1, 5*time.Second)
	r2 := pollTaskResult(server2URL, taskID2, 5*time.Second)

	ok := true
	if r1 != nil && r1.ECDSAPublicKey != "" {
		fmt.Println("  FAIL: server1 should not have produced ECDSA key")
		ok = false
	} else {
		fmt.Println("  OK: server1 failed as expected")
	}
	if r2 != nil && r2.ECDSAPublicKey != "" {
		fmt.Println("  FAIL: server2 should not have produced ECDSA key")
		ok = false
	} else {
		fmt.Println("  OK: server2 failed as expected")
	}
	return ok
}

func test2_PartialSuccess() (string, bool) {
	sessionID := uuid.New().String()
	hexKey := randomHex(32)
	encSetup := createAndEncryptSetup(hexKey)

	taskID1 := postBatch(server1URL, sessionID, hexKey, party1, []string{"ecdsa", "eddsa", "frozt"}, "")
	taskID2 := postBatch(server2URL, sessionID, hexKey, party2, []string{"ecdsa", "eddsa", "frozt"}, "")
	waitForParties(relayURL, sessionID, 2, 30*time.Second)
	uploadSetupMessage(relayURL, sessionID, encSetup)
	startSession(relayURL, sessionID, parties)
	// do NOT send frozt metadata — frozt should fail

	r1 := pollTaskResult(server1URL, taskID1, 30*time.Second)
	if r1 == nil {
		fmt.Println("  FAIL: no result from server1")
		return "", false
	}

	ok := true
	ecdsaPK := r1.ECDSAPublicKey
	fmt.Printf("  ECDSA pubkey: %s\n", ecdsaPK)

	for _, phase := range r1.Phases {
		switch phase.Name {
		case "ecdsa", "eddsa":
			if !phase.Success {
				fmt.Printf("  FAIL: %s should have succeeded: %s\n", phase.Name, phase.Error)
				ok = false
			} else {
				fmt.Printf("  OK: %s succeeded\n", phase.Name)
			}
		case "frozt":
			if phase.Success {
				fmt.Printf("  FAIL: frozt should have failed (no metadata sent)\n")
				ok = false
			} else {
				fmt.Printf("  OK: frozt failed as expected: %s\n", phase.Error)
			}
		}
	}

	_ = pollTaskResult(server2URL, taskID2, 30*time.Second)
	return ecdsaPK, ok
}

func test3_Append(ecdsaPK string) bool {
	if ecdsaPK == "" {
		fmt.Println("  SKIP: no ECDSA pubkey from Test 2")
		return false
	}

	sessionID := uuid.New().String()
	hexKey := randomHex(32)
	encSetup := createAndEncryptSetup(hexKey)

	taskID1 := postBatch(server1URL, sessionID, hexKey, party1, []string{"ecdsa", "eddsa", "frozt", "fromt"}, ecdsaPK)
	taskID2 := postBatch(server2URL, sessionID, hexKey, party2, []string{"ecdsa", "eddsa", "frozt", "fromt"}, ecdsaPK)
	waitForParties(relayURL, sessionID, 2, 30*time.Second)
	uploadSetupMessage(relayURL, sessionID, encSetup)
	startSession(relayURL, sessionID, parties)
	sendFroztMetadata(relayURL, sessionID, hexKey, parties)
	sendFromtMetadata(relayURL, sessionID, hexKey, parties)

	r1 := pollTaskResult(server1URL, taskID1, 30*time.Second)
	if r1 == nil {
		fmt.Println("  FAIL: no result from server1")
		return false
	}

	ok := true
	for _, phase := range r1.Phases {
		switch phase.Name {
		case "ecdsa", "eddsa":
			if !phase.Skipped {
				fmt.Printf("  FAIL: %s should have been skipped (already in vault)\n", phase.Name)
				ok = false
			} else {
				fmt.Printf("  OK: %s skipped\n", phase.Name)
			}
		case "frozt", "fromt":
			if !phase.Success {
				fmt.Printf("  FAIL: %s should have succeeded: %s\n", phase.Name, phase.Error)
				ok = false
			} else {
				fmt.Printf("  OK: %s succeeded\n", phase.Name)
			}
		}
	}

	_ = pollTaskResult(server2URL, taskID2, 30*time.Second)
	return ok
}

func test4_Idempotent(ecdsaPK string) bool {
	if ecdsaPK == "" {
		fmt.Println("  SKIP: no ECDSA pubkey from Test 2")
		return false
	}

	sessionID := uuid.New().String()
	hexKey := randomHex(32)

	taskID1 := postBatch(server1URL, sessionID, hexKey, party1, []string{"ecdsa"}, ecdsaPK)

	r1 := pollTaskResult(server1URL, taskID1, 15*time.Second)
	if r1 == nil {
		fmt.Println("  FAIL: no result from server1")
		return false
	}

	ok := true
	for _, phase := range r1.Phases {
		if !phase.Skipped {
			fmt.Printf("  FAIL: %s should have been skipped\n", phase.Name)
			ok = false
		} else {
			fmt.Printf("  OK: %s skipped\n", phase.Name)
		}
	}
	return ok
}

func test5_FullBatch() bool {
	sessionID := uuid.New().String()
	hexKey := randomHex(32)
	encSetup := createAndEncryptSetup(hexKey)

	taskID1 := postBatch(server1URL, sessionID, hexKey, party1, []string{"ecdsa", "eddsa", "frozt", "fromt"}, "")
	taskID2 := postBatch(server2URL, sessionID, hexKey, party2, []string{"ecdsa", "eddsa", "frozt", "fromt"}, "")
	waitForParties(relayURL, sessionID, 2, 30*time.Second)
	uploadSetupMessage(relayURL, sessionID, encSetup)
	startSession(relayURL, sessionID, parties)
	sendFroztMetadata(relayURL, sessionID, hexKey, parties)
	sendFromtMetadata(relayURL, sessionID, hexKey, parties)

	r1 := pollTaskResult(server1URL, taskID1, 30*time.Second)
	if r1 == nil {
		fmt.Println("  FAIL: no result from server1")
		return false
	}

	ok := true
	for _, phase := range r1.Phases {
		if !phase.Success {
			fmt.Printf("  FAIL: %s should have succeeded: %s\n", phase.Name, phase.Error)
			ok = false
		} else {
			fmt.Printf("  OK: %s succeeded (pk: %s...)\n", phase.Name, phase.PublicKey[:16])
		}
	}

	r2 := pollTaskResult(server2URL, taskID2, 30*time.Second)
	if r2 == nil {
		fmt.Println("  FAIL: no result from server2")
		return false
	}

	if r1.ECDSAPublicKey != r2.ECDSAPublicKey {
		fmt.Printf("  FAIL: ECDSA keys don't match: %s vs %s\n", r1.ECDSAPublicKey, r2.ECDSAPublicKey)
		ok = false
	} else {
		fmt.Printf("  OK: both parties produced matching ECDSA key\n")
	}

	if r1.EDDSAPublicKey != r2.EDDSAPublicKey {
		fmt.Printf("  FAIL: EDDSA keys don't match\n")
		ok = false
	} else {
		fmt.Printf("  OK: both parties produced matching EDDSA key\n")
	}

	return ok
}

// --- helpers ---

type TaskResultResponse struct {
	ECDSAPublicKey string                       `json:"ECDSAPublicKey"`
	EDDSAPublicKey string                       `json:"EDDSAPublicKey"`
	Phases         []service.KeygenPhaseStatus  `json:"Phases"`
}

func createAndEncryptSetup(hexKey string) string {
	wrapper := service.NewMPCWrapperImp(false, false)
	keyID := randomBytes(32)
	idsBytes := encodePartyIDs(parties)
	setupMsg, err := wrapper.KeygenSetupMsgNew(mldsaSession.MlDsa44, len(parties), keyID, idsBytes)
	if err != nil {
		fatal("KeygenSetupMsgNew: %v", err)
	}
	return encryptAndEncode(setupMsg, hexKey)
}

func postBatch(serverURL, sessionID, hexKey, localPartyID string, protocols []string, publicKey string) string {
	reqBody := map[string]any{
		"name":                "test-vault",
		"session_id":          sessionID,
		"hex_encryption_key":  hexKey,
		"hex_chain_code":      randomHex(32),
		"local_party_id":      localPartyID,
		"encryption_password": "test-password",
		"email":               "test@test.com",
		"lib_type":            1,
		"protocols":           protocols,
	}
	if publicKey != "" {
		reqBody["public_key"] = publicKey
	}
	body, _ := json.Marshal(reqBody)
	resp, err := http.Post(serverURL+"/vault/batch", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("  POST failed: %v\n", err)
		return ""
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	var result map[string]string
	_ = json.Unmarshal(respBody, &result)
	taskID := result["task_id"]
	fmt.Printf("  POST %s → %d (task: %s)\n", serverURL, resp.StatusCode, taskID)
	return taskID
}

func pollTaskResult(serverURL, taskID string, timeout time.Duration) *TaskResultResponse {
	if taskID == "" {
		return nil
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(serverURL + "/vault/task/" + taskID)
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			var result TaskResultResponse
			_ = json.Unmarshal(body, &result)
			return &result
		}
		if resp.StatusCode == http.StatusInternalServerError {
			fmt.Printf("  Task failed: %s\n", string(body))
			return nil
		}
		time.Sleep(time.Second)
	}
	fmt.Printf("  Task %s timed out\n", taskID)
	return nil
}

func sendFroztMetadata(relayURL, sessionID, hexKey string, parties []string) {
	_, metadataBytes, err := frozt.KeygenMetadataCreate(0)
	if err != nil {
		fmt.Printf("  WARNING: frozt metadata create failed: %v\n", err)
		return
	}
	for _, party := range parties {
		sendRelayMessage(relayURL, sessionID, hexKey, "coordinator", party, metadataBytes, "p-frozt-metadata")
	}
	metadataHash, err := frozt.KeygenMetadataHash(metadataBytes)
	if err != nil {
		return
	}
	time.Sleep(200 * time.Millisecond)
	for _, party := range parties {
		sendRelayMessage(relayURL, sessionID, hexKey, "coordinator", party, metadataHash, "p-frozt-metadata-hash")
	}
}

func sendFromtMetadata(relayURL, sessionID, hexKey string, parties []string) {
	meta := make([]byte, 9)
	meta[0] = 1
	binary.LittleEndian.PutUint64(meta[1:], 0)
	for _, party := range parties {
		sendRelayMessage(relayURL, sessionID, hexKey, "coordinator", party, meta, "p-fromt-metadata")
	}
}

func sendRelayMessage(relayURL, sessionID, hexKey, from, to string, data []byte, messageID string) {
	innerB64 := base64.StdEncoding.EncodeToString(data)
	encrypted, err := encryptGCM(innerB64, hexKey)
	if err != nil {
		return
	}
	body := base64.StdEncoding.EncodeToString([]byte(encrypted))
	hash := md5.Sum([]byte(body))
	msg, _ := json.Marshal(struct {
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
		Hash:      hex.EncodeToString(hash[:]),
	})
	req, _ := http.NewRequest("POST", relayURL+"/message/"+sessionID, bytes.NewReader(msg))
	req.Header.Set("Content-Type", "application/json")
	if messageID != "" {
		req.Header.Set("message_id", messageID)
	}
	resp, _ := http.DefaultClient.Do(req)
	if resp != nil {
		resp.Body.Close()
	}
}

func waitForParties(relayURL, sessionID string, expected int, timeout time.Duration) {
	url := relayURL + "/" + sessionID
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		var p []string
		_ = json.Unmarshal(body, &p)
		if len(p) >= expected {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	fatal("timeout waiting for %d parties", expected)
}

func uploadSetupMessage(relayURL, sessionID, payload string) {
	req, _ := http.NewRequest("POST", relayURL+"/setup-message/"+sessionID, strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fatal("upload setup: %v", err)
	}
	resp.Body.Close()
}

func startSession(relayURL, sessionID string, parties []string) {
	body, _ := json.Marshal(parties)
	resp, err := http.Post(relayURL+"/start/"+sessionID, "application/json", bytes.NewReader(body))
	if err != nil {
		fatal("start session: %v", err)
	}
	resp.Body.Close()
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
	passwd, _ := hex.DecodeString(hexKey)
	hash := sha256.Sum256(passwd)
	block, _ := aes.NewCipher(hash[:])
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	_, _ = io.ReadFull(rand.Reader, nonce)
	return string(gcm.Seal(nonce, nonce, []byte(plainText), nil)), nil
}

func encryptAndEncode(data []byte, hexKey string) string {
	inner := base64.StdEncoding.EncodeToString(data)
	encrypted, _ := encryptGCM(inner, hexKey)
	return base64.StdEncoding.EncodeToString([]byte(encrypted))
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
	os.Exit(1)
}
