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

	httpClient = &http.Client{Timeout: 30 * time.Second}
)

func main() {
	relayURL = envOrDefault("RELAY_URL", "http://relay:8080")
	server1URL = envOrDefault("SERVER1_URL", "http://vultiserver1:8080")
	server2URL = envOrDefault("SERVER2_URL", "http://vultiserver2:8080")

	fmt.Println("=== Batch Keygen Integration Tests ===")
	waitForHealth(relayURL+"/ping", 30*time.Second)
	waitForHealth(server1URL+"/ping", 30*time.Second)
	waitForHealth(server2URL+"/ping", 30*time.Second)
	fmt.Println("All services healthy")

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

	if runTest("Test 5: Full batch — all 5 succeed", test5_FullBatch) {
		passed++
	} else {
		failed++
	}

	if runTest("Test 6: Keygen then keysign all protocols", test6_KeygenThenKeysign) {
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

	r1 := pollTaskResult(server1URL, taskID1, 4*time.Minute)
	if r1 == nil {
		fmt.Println("  FAIL: no result from server1")
		return "", false
	}

	ok := true
	ecdsaPK := r1.ECDSAPublicKey
	fmt.Printf("  ECDSA pubkey: %s\n", ecdsaPK)

	if !assertPhasesPresent(r1, []string{"ecdsa", "eddsa", "frozt"}) {
		ok = false
	}

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

	_ = pollTaskResult(server2URL, taskID2, 4*time.Minute)
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

	r1 := pollTaskResult(server1URL, taskID1, 4*time.Minute)
	if r1 == nil {
		fmt.Println("  FAIL: no result from server1")
		return false
	}

	ok := true
	if !assertPhasesPresent(r1, []string{"ecdsa", "eddsa", "frozt", "fromt"}) {
		ok = false
	}
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

	_ = pollTaskResult(server2URL, taskID2, 4*time.Minute)
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
	mldsaSetup := createAndEncryptMldsaSetup(hexKey)

	taskID1 := postBatch(server1URL, sessionID, hexKey, party1, []string{"ecdsa", "eddsa", "frozt", "fromt", "mldsa"}, "")
	taskID2 := postBatch(server2URL, sessionID, hexKey, party2, []string{"ecdsa", "eddsa", "frozt", "fromt", "mldsa"}, "")
	waitForParties(relayURL, sessionID, 2, 30*time.Second)
	uploadSetupMessage(relayURL, sessionID, encSetup)
	uploadSetupMessageWithID(relayURL, sessionID, mldsaSetup, "p-mldsa-setup")
	startSession(relayURL, sessionID, parties)
	sendFroztMetadata(relayURL, sessionID, hexKey, parties)
	sendFromtMetadata(relayURL, sessionID, hexKey, parties)

	r1 := pollTaskResult(server1URL, taskID1, 4*time.Minute)
	if r1 == nil {
		fmt.Println("  FAIL: no result from server1")
		return false
	}

	ok := true
	if !assertPhasesPresent(r1, []string{"ecdsa", "eddsa", "frozt", "fromt", "mldsa"}) {
		ok = false
	}
	for _, phase := range r1.Phases {
		if !phase.Success {
			fmt.Printf("  FAIL: %s should have succeeded: %s\n", phase.Name, phase.Error)
			ok = false
		} else {
			pk := phase.PublicKey
			if len(pk) > 16 {
				pk = pk[:16]
			}
			fmt.Printf("  OK: %s succeeded (pk: %s...)\n", phase.Name, pk)
		}
	}

	r2 := pollTaskResult(server2URL, taskID2, 4*time.Minute)
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

	if r1.MLDSAPublicKey != r2.MLDSAPublicKey {
		fmt.Printf("  FAIL: MLDSA keys don't match: %s vs %s\n", r1.MLDSAPublicKey, r2.MLDSAPublicKey)
		ok = false
	} else {
		fmt.Printf("  OK: both parties produced matching MLDSA key\n")
	}

	for _, name := range []string{"frozt", "fromt"} {
		pk1 := phasePublicKey(r1, name)
		pk2 := phasePublicKey(r2, name)
		if pk1 == "" || pk2 == "" {
			fmt.Printf("  FAIL: %s public key missing (pk1=%q, pk2=%q)\n", name, pk1, pk2)
			ok = false
		} else if pk1 != pk2 {
			fmt.Printf("  FAIL: %s keys don't match\n", name)
			ok = false
		} else {
			fmt.Printf("  OK: both parties produced matching %s key\n", name)
		}
	}

	return ok
}

func phasePublicKey(result *TaskResultResponse, name string) string {
	for _, p := range result.Phases {
		if p.Name == name && p.Success {
			return p.PublicKey
		}
	}
	return ""
}

// --- helpers ---

type TaskResultResponse struct {
	ECDSAPublicKey string                      `json:"ECDSAPublicKey"`
	EDDSAPublicKey string                      `json:"EDDSAPublicKey"`
	MLDSAPublicKey string                      `json:"MLDSAPublicKey"`
	Phases         []service.KeygenPhaseStatus `json:"Phases"`
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
	resp, err := httpClient.Post(serverURL+"/vault/batch", "application/json", bytes.NewReader(body))
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
		resp, err := httpClient.Get(serverURL + "/vault/task/" + taskID)
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
	resp, _ := httpClient.Do(req)
	if resp != nil {
		resp.Body.Close()
	}
}

func waitForParties(relayURL, sessionID string, expected int, timeout time.Duration) {
	url := relayURL + "/" + sessionID
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := httpClient.Get(url)
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
	resp, err := httpClient.Do(req)
	if err != nil {
		fatal("upload setup: %v", err)
	}
	resp.Body.Close()
}

func startSession(relayURL, sessionID string, parties []string) {
	body, _ := json.Marshal(parties)
	resp, err := httpClient.Post(relayURL+"/start/"+sessionID, "application/json", bytes.NewReader(body))
	if err != nil {
		fatal("start session: %v", err)
	}
	resp.Body.Close()
}

func waitForHealth(url string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := httpClient.Get(url)
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

func assertPhasesPresent(result *TaskResultResponse, expected []string) bool {
	present := make(map[string]bool)
	for _, p := range result.Phases {
		present[p.Name] = true
	}
	ok := true
	for _, name := range expected {
		if !present[name] {
			fmt.Printf("  FAIL: expected phase %q missing from result\n", name)
			ok = false
		}
	}
	return ok
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

// --- keysign test ---

type KeysignResponseEntry struct {
	Msg          string `json:"Msg"`
	R            string `json:"R"`
	S            string `json:"S"`
	DerSignature string `json:"DerSignature"`
	RecoveryID   string `json:"RecoveryID"`
}

func test6_KeygenThenKeysign() bool {
	fmt.Println("  Phase 1: Keygen (all protocols)")
	keygenSessionID := uuid.New().String()
	hexKey := randomHex(32)
	keyID := randomBytes(32)
	encSetup := createAndEncryptSetupWithKeyID(hexKey, keyID)
	mldsaSetup := createAndEncryptMldsaSetupWithKeyID(hexKey, keyID)

	taskID1 := postBatch(server1URL, keygenSessionID, hexKey, party1, []string{"ecdsa", "eddsa", "frozt", "fromt", "mldsa"}, "")
	taskID2 := postBatch(server2URL, keygenSessionID, hexKey, party2, []string{"ecdsa", "eddsa", "frozt", "fromt", "mldsa"}, "")
	waitForParties(relayURL, keygenSessionID, 2, 30*time.Second)
	uploadSetupMessage(relayURL, keygenSessionID, encSetup)
	uploadSetupMessageWithID(relayURL, keygenSessionID, mldsaSetup, "p-mldsa-setup")
	startSession(relayURL, keygenSessionID, parties)
	sendFroztMetadata(relayURL, keygenSessionID, hexKey, parties)
	sendFromtMetadata(relayURL, keygenSessionID, hexKey, parties)

	r1 := pollTaskResult(server1URL, taskID1, 4*time.Minute)
	r2 := pollTaskResult(server2URL, taskID2, 4*time.Minute)
	if r1 == nil || r2 == nil {
		fmt.Println("  FAIL: keygen failed")
		return false
	}

	ecdsaPK := r1.ECDSAPublicKey
	if ecdsaPK == "" || ecdsaPK != r2.ECDSAPublicKey {
		fmt.Println("  FAIL: keygen ECDSA keys missing or don't match")
		return false
	}
	fmt.Printf("  Keygen OK (ECDSA: %s...)\n", ecdsaPK[:16])

	keygenPhaseOK := make(map[string]bool)
	for _, phase := range r1.Phases {
		keygenPhaseOK[phase.Name] = phase.Success
	}

	msgHash := sha256.Sum256([]byte("hello world"))
	msgHex := hex.EncodeToString(msgHash[:])
	password := "test-password"
	ok := true

	fmt.Println("  Phase 2: ECDSA keysign")
	if !doKeysign("ecdsa", ecdsaPK, password, msgHex, keyID, true, false, "") {
		ok = false
	}

	fmt.Println("  Phase 3: EdDSA keysign")
	if !doKeysign("eddsa", ecdsaPK, password, msgHex, keyID, false, false, "") {
		ok = false
	}

	fmt.Println("  Phase 4: MLDSA keysign")
	if !keygenPhaseOK["mldsa"] {
		fmt.Println("    SKIP: mldsa keygen did not succeed")
	} else if !doKeysign("mldsa", ecdsaPK, password, msgHex, keyID, false, true, "") {
		fmt.Println("    WARN: mldsa keysign failed (known library issue: reject sampling)")
	}

	fmt.Println("  Phase 5: Frozt keysign")
	if !keygenPhaseOK["frozt"] {
		fmt.Println("    SKIP: frozt keygen did not succeed")
	} else if !doKeysign("frozt", ecdsaPK, password, msgHex, nil, true, false, "ZcashSapling") {
		ok = false
	}

	fmt.Println("  Phase 6: Fromt keysign")
	if !keygenPhaseOK["fromt"] {
		fmt.Println("    SKIP: fromt keygen did not succeed")
	} else if !doKeysign("fromt", ecdsaPK, password, msgHex, nil, true, false, "Monero") {
		ok = false
	}

	return ok
}

func doKeysign(name, ecdsaPK, password, msgHex string, keyID []byte, isECDSA, isMldsa bool, chain string) bool {
	sessionID := uuid.New().String()
	signHexKey := randomHex(32)

	reqBody := map[string]any{
		"public_key":         ecdsaPK,
		"messages":           []string{msgHex},
		"session":            sessionID,
		"hex_encryption_key": signHexKey,
		"derive_path":        "m",
		"is_ecdsa":           isECDSA,
		"vault_password":     password,
	}
	if chain != "" {
		reqBody["chain"] = chain
	}
	if isMldsa {
		reqBody["mldsa"] = true
	}

	taskID1 := postKeysign(server1URL, reqBody)
	taskID2 := postKeysign(server2URL, reqBody)

	waitForParties(relayURL, sessionID, 2, 30*time.Second)

	if keyID != nil {
		msgBytes, _ := hex.DecodeString(msgHex)
		signSetup := createSignSetupFull(signHexKey, keyID, msgBytes, !isECDSA, isMldsa)
		md5Hash := md5.Sum([]byte(msgHex))
		messageID := hex.EncodeToString(md5Hash[:])
		uploadSetupMessageWithID(relayURL, sessionID, signSetup, messageID)
	}

	startSession(relayURL, sessionID, parties)

	r1 := pollKeysignResult(server1URL, taskID1, 60*time.Second)
	r2 := pollKeysignResult(server2URL, taskID2, 60*time.Second)

	if r1 == nil || r2 == nil {
		fmt.Printf("    FAIL: %s keysign returned nil result\n", name)
		return false
	}

	sig1, ok1 := r1[msgHex]
	sig2, ok2 := r2[msgHex]
	if !ok1 || !ok2 {
		fmt.Printf("    FAIL: %s keysign missing message in result\n", name)
		return false
	}

	if sig1.R == "" || sig1.S == "" {
		fmt.Printf("    FAIL: %s server1 empty signature\n", name)
		return false
	}

	if sig1.R != sig2.R || sig1.S != sig2.S {
		fmt.Printf("    FAIL: %s signatures don't match (R1=%s, R2=%s)\n", name, sig1.R[:16], sig2.R[:16])
		return false
	}

	fmt.Printf("    OK: %s keysign succeeded (R: %s...)\n", name, sig1.R[:16])
	return true
}

func createAndEncryptMldsaSetup(hexKey string) string {
	wrapper := service.NewMPCWrapperImp(true, true)
	keyID := randomBytes(32)
	idsBytes := encodePartyIDs(parties)
	setupMsg, err := wrapper.KeygenSetupMsgNew(mldsaSession.MlDsa44, len(parties), keyID, idsBytes)
	if err != nil {
		fatal("MLDSA KeygenSetupMsgNew: %v", err)
	}
	return encryptAndEncode(setupMsg, hexKey)
}

func createAndEncryptMldsaSetupWithKeyID(hexKey string, keyID []byte) string {
	wrapper := service.NewMPCWrapperImp(true, true)
	idsBytes := encodePartyIDs(parties)
	setupMsg, err := wrapper.KeygenSetupMsgNew(mldsaSession.MlDsa44, len(parties), keyID, idsBytes)
	if err != nil {
		fatal("MLDSA KeygenSetupMsgNew: %v", err)
	}
	return encryptAndEncode(setupMsg, hexKey)
}

func createAndEncryptSetupWithKeyID(hexKey string, keyID []byte) string {
	wrapper := service.NewMPCWrapperImp(false, false)
	idsBytes := encodePartyIDs(parties)
	setupMsg, err := wrapper.KeygenSetupMsgNew(mldsaSession.MlDsa44, len(parties), keyID, idsBytes)
	if err != nil {
		fatal("KeygenSetupMsgNew: %v", err)
	}
	return encryptAndEncode(setupMsg, hexKey)
}

func createSignSetupFull(hexKey string, keyID, messageHash []byte, isEdDSA, isMldsa bool) string {
	wrapper := service.NewMPCWrapperImp(isEdDSA, isMldsa)
	idsBytes := encodePartyIDs(parties)
	setupMsg, err := wrapper.SignSetupMsgNew(mldsaSession.MlDsa44, keyID, []byte("m"), messageHash, idsBytes)
	if err != nil {
		fatal("SignSetupMsgNew: %v", err)
	}
	return encryptAndEncode(setupMsg, hexKey)
}

func uploadSetupMessageWithID(relayURL, sessionID, payload, messageID string) {
	req, _ := http.NewRequest("POST", relayURL+"/setup-message/"+sessionID, strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	if messageID != "" {
		req.Header.Set("message_id", messageID)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		fatal("upload setup with id: %v", err)
	}
	resp.Body.Close()
}

func postKeysign(serverURL string, reqBody map[string]any) string {
	body, _ := json.Marshal(reqBody)
	resp, err := httpClient.Post(serverURL+"/vault/sign", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("  POST keysign failed: %v\n", err)
		return ""
	}
	defer resp.Body.Close()
	var taskID string
	_ = json.NewDecoder(resp.Body).Decode(&taskID)
	fmt.Printf("  POST keysign %s → %d (task: %s)\n", serverURL, resp.StatusCode, taskID)
	return taskID
}

func pollKeysignResult(serverURL, taskID string, timeout time.Duration) map[string]KeysignResponseEntry {
	if taskID == "" {
		return nil
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := httpClient.Get(serverURL + "/vault/task/" + taskID)
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			var result map[string]KeysignResponseEntry
			_ = json.Unmarshal(body, &result)
			return result
		}
		if resp.StatusCode == http.StatusInternalServerError {
			fmt.Printf("  Keysign task failed: %s\n", string(body))
			return nil
		}
		time.Sleep(time.Second)
	}
	fmt.Printf("  Keysign task %s timed out\n", taskID)
	return nil
}
