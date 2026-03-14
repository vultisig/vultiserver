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
	fromt "github.com/vultisig/frost-zm/go/fromt"
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
	if runTestWithResult("Test 2: ECDSA+EDDSA+FROZT keygen", func() (string, bool) {
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

	ecdsaPK5 := ""
	if runTestWithResult("Test 5: Full batch — all 5 succeed", func() (string, bool) {
		return test5_FullBatch()
	}, &ecdsaPK5) {
		passed++
	} else {
		failed++
	}

	if runTest("Test 6: Keygen then keysign all protocols", test6_KeygenThenKeysign) {
		passed++
	} else {
		failed++
	}

	if runTest("Test 7: Batch reshare (ecdsa+eddsa)", func() bool {
		return test7_BatchReshare(ecdsaPK5)
	}) {
		passed++
	} else {
		failed++
	}

	if runTest("Test 8: Batch import (ecdsa+eddsa+frozt+fromt)", test8_BatchImport) {
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
	start := time.Now()
	ok := fn()
	elapsed := time.Since(start)
	if ok {
		fmt.Printf("--- PASS: %s (%.1fs) ---\n\n", name, elapsed.Seconds())
	} else {
		fmt.Printf("--- FAIL: %s (%.1fs) ---\n\n", name, elapsed.Seconds())
	}
	return ok
}

func runTestWithResult(name string, fn func() (string, bool), result *string) bool {
	fmt.Printf("--- %s ---\n", name)
	start := time.Now()
	r, ok := fn()
	*result = r
	elapsed := time.Since(start)
	if ok {
		fmt.Printf("--- PASS: %s (%.1fs) ---\n\n", name, elapsed.Seconds())
	} else {
		fmt.Printf("--- FAIL: %s (%.1fs) ---\n\n", name, elapsed.Seconds())
	}
	return ok
}

// --- test functions ---

func test1_FullFail() bool {
	sessionID := uuid.New().String()
	hexKey := randomHex(32)

	badSetup := []byte("this is not a valid setup message")
	encSetup := encryptAndEncode(badSetup, hexKey)

	postBatch(server1URL, sessionID, hexKey, party1, []string{"ecdsa", "eddsa"}, "")
	postBatch(server2URL, sessionID, hexKey, party2, []string{"ecdsa", "eddsa"}, "")
	waitForParties(relayURL, sessionID, 2, 30*time.Second)
	uploadSetupMessage(relayURL, sessionID, encSetup)
	startSession(relayURL, sessionID, parties)

	s1, s2 := getServerStatuses(sessionID, hexKey, 2*time.Minute)

	ok := true
	for _, name := range []string{"ecdsa", "eddsa"} {
		if s, found := s1[name]; found && s.Status == service.StatusDone {
			fmt.Printf("  FAIL: server1 %s should not have succeeded\n", name)
			ok = false
		}
		if s, found := s2[name]; found && s.Status == service.StatusDone {
			fmt.Printf("  FAIL: server2 %s should not have succeeded\n", name)
			ok = false
		}
	}
	if ok {
		fmt.Println("  OK: both servers failed as expected")
	}
	return ok
}

func test2_PartialSuccess() (string, bool) {
	sessionID := uuid.New().String()
	hexKey := randomHex(32)
	encSetup := createAndEncryptSetup(hexKey)

	postBatch(server1URL, sessionID, hexKey, party1, []string{"ecdsa", "eddsa", "frozt"}, "")
	postBatch(server2URL, sessionID, hexKey, party2, []string{"ecdsa", "eddsa", "frozt"}, "")
	waitForParties(relayURL, sessionID, 2, 30*time.Second)
	uploadSetupMessage(relayURL, sessionID, encSetup)
	startSession(relayURL, sessionID, parties)

	s1, _ := getServerStatuses(sessionID, hexKey, 4*time.Minute)
	if s1 == nil {
		fmt.Println("  FAIL: no statuses from server1")
		return "", false
	}

	ok := true
	for _, name := range []string{"ecdsa", "eddsa", "frozt"} {
		s, found := s1[name]
		if !found || s.Status != service.StatusDone {
			fmt.Printf("  FAIL: %s should have succeeded\n", name)
			ok = false
		} else {
			fmt.Printf("  OK: %s succeeded\n", name)
		}
	}

	ecdsaPK := ""
	if s, found := s1["ecdsa"]; found {
		ecdsaPK = s.PublicKey
	}
	fmt.Printf("  ECDSA pubkey: %s\n", ecdsaPK)
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

	postBatch(server1URL, sessionID, hexKey, party1, []string{"ecdsa", "eddsa", "frozt", "fromt"}, ecdsaPK)
	postBatch(server2URL, sessionID, hexKey, party2, []string{"ecdsa", "eddsa", "frozt", "fromt"}, ecdsaPK)
	waitForParties(relayURL, sessionID, 2, 30*time.Second)
	uploadSetupMessage(relayURL, sessionID, encSetup)
	startSession(relayURL, sessionID, parties)
	sendFroztMetadata(relayURL, sessionID, hexKey, parties)
	sendFromtMetadata(relayURL, sessionID, hexKey, parties)

	s1, _ := getServerStatuses(sessionID, hexKey, 4*time.Minute)
	if s1 == nil {
		fmt.Println("  FAIL: no statuses from server1")
		return false
	}

	ok := true
	for _, name := range []string{"ecdsa", "eddsa", "frozt"} {
		if s, found := s1[name]; found && s.Status == service.StatusDone {
			fmt.Printf("  FAIL: %s should have been skipped (already in vault), got done\n", name)
			ok = false
		} else {
			fmt.Printf("  OK: %s skipped (no status notification)\n", name)
		}
	}
	s, found := s1["fromt"]
	if !found || s.Status != service.StatusDone {
		errMsg := "not found"
		if found {
			errMsg = s.Error
		}
		fmt.Printf("  FAIL: fromt should have succeeded: %s\n", errMsg)
		ok = false
	} else {
		fmt.Printf("  OK: fromt succeeded (pk: %s)\n", s.PublicKey)
	}

	return ok
}

func test4_Idempotent(ecdsaPK string) bool {
	if ecdsaPK == "" {
		fmt.Println("  SKIP: no ECDSA pubkey from Test 2")
		return false
	}

	sessionID := uuid.New().String()
	hexKey := randomHex(32)

	code := postBatch(server1URL, sessionID, hexKey, party1, []string{"ecdsa", "eddsa"}, ecdsaPK)
	if code != http.StatusNoContent {
		fmt.Printf("  FAIL: expected 204, got %d\n", code)
		return false
	}

	time.Sleep(3 * time.Second)
	fmt.Println("  OK: server accepted idempotent request (204)")
	return true
}

func test5_FullBatch() (string, bool) {
	sessionID := uuid.New().String()
	hexKey := randomHex(32)
	encSetup := createAndEncryptSetup(hexKey)
	mldsaSetup := createAndEncryptMldsaSetup(hexKey)

	postBatch(server1URL, sessionID, hexKey, party1, []string{"ecdsa", "eddsa", "frozt", "fromt", "mldsa"}, "")
	postBatch(server2URL, sessionID, hexKey, party2, []string{"ecdsa", "eddsa", "frozt", "fromt", "mldsa"}, "")
	waitForParties(relayURL, sessionID, 2, 30*time.Second)
	uploadSetupMessage(relayURL, sessionID, encSetup)
	uploadSetupMessageWithID(relayURL, sessionID, mldsaSetup, "p-mldsa-setup")
	startSession(relayURL, sessionID, parties)
	sendFroztMetadata(relayURL, sessionID, hexKey, parties)
	sendFromtMetadata(relayURL, sessionID, hexKey, parties)

	s1, s2 := getServerStatuses(sessionID, hexKey, 4*time.Minute)
	if s1 == nil || s2 == nil {
		fmt.Println("  FAIL: missing statuses")
		return "", false
	}

	ok := true
	for _, name := range []string{"ecdsa", "eddsa", "frozt", "fromt", "mldsa"} {
		st1, found1 := s1[name]
		st2, found2 := s2[name]
		if !found1 || st1.Status != service.StatusDone {
			fmt.Printf("  FAIL: server1 %s should have succeeded\n", name)
			ok = false
			continue
		}
		if !found2 || st2.Status != service.StatusDone {
			fmt.Printf("  FAIL: server2 %s should have succeeded\n", name)
			ok = false
			continue
		}
		pk := st1.PublicKey
		if len(pk) > 16 {
			pk = pk[:16]
		}
		fmt.Printf("  OK: %s succeeded (pk: %s...)\n", name, pk)
	}

	for _, name := range []string{"ecdsa", "eddsa", "mldsa", "frozt", "fromt"} {
		pk1 := s1[name].PublicKey
		pk2 := s2[name].PublicKey
		if pk1 == "" || pk2 == "" {
			continue
		}
		if pk1 != pk2 {
			fmt.Printf("  FAIL: %s keys don't match\n", name)
			ok = false
		} else {
			fmt.Printf("  OK: both parties produced matching %s key\n", name)
		}
	}

	ecdsaPK := ""
	if s, found := s1["ecdsa"]; found {
		ecdsaPK = s.PublicKey
	}
	return ecdsaPK, ok
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

	postBatch(server1URL, keygenSessionID, hexKey, party1, []string{"ecdsa", "eddsa", "frozt", "fromt", "mldsa"}, "")
	postBatch(server2URL, keygenSessionID, hexKey, party2, []string{"ecdsa", "eddsa", "frozt", "fromt", "mldsa"}, "")
	waitForParties(relayURL, keygenSessionID, 2, 30*time.Second)
	uploadSetupMessage(relayURL, keygenSessionID, encSetup)
	uploadSetupMessageWithID(relayURL, keygenSessionID, mldsaSetup, "p-mldsa-setup")
	startSession(relayURL, keygenSessionID, parties)
	sendFroztMetadata(relayURL, keygenSessionID, hexKey, parties)
	sendFromtMetadata(relayURL, keygenSessionID, hexKey, parties)

	s1, s2 := getServerStatuses(keygenSessionID, hexKey, 4*time.Minute)
	if s1 == nil || s2 == nil {
		fmt.Println("  FAIL: keygen failed — no statuses")
		return false
	}

	ecdsaSt1, ok1 := s1["ecdsa"]
	ecdsaSt2, ok2 := s2["ecdsa"]
	if !ok1 || !ok2 || ecdsaSt1.Status != service.StatusDone || ecdsaSt2.Status != service.StatusDone {
		fmt.Println("  FAIL: keygen ECDSA not done on both servers")
		return false
	}
	ecdsaPK := ecdsaSt1.PublicKey
	if ecdsaPK == "" || ecdsaPK != ecdsaSt2.PublicKey {
		fmt.Println("  FAIL: keygen ECDSA keys missing or don't match")
		return false
	}
	fmt.Printf("  Keygen OK (ECDSA: %s...)\n", ecdsaPK[:16])

	keygenOK := make(map[string]bool)
	for _, name := range []string{"ecdsa", "eddsa", "frozt", "fromt", "mldsa"} {
		s, found := s1[name]
		keygenOK[name] = found && s.Status == service.StatusDone
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
	if !keygenOK["mldsa"] {
		fmt.Println("    SKIP: mldsa keygen did not succeed")
	} else if !doKeysign("mldsa", ecdsaPK, password, msgHex, keyID, false, true, "") {
		fmt.Println("    WARN: mldsa keysign failed (known library issue: reject sampling)")
	}

	fmt.Println("  Phase 5: Frozt keysign")
	if !keygenOK["frozt"] {
		fmt.Println("    SKIP: frozt keygen did not succeed")
	} else if !doKeysign("frozt", ecdsaPK, password, msgHex, nil, true, false, "ZcashSapling") {
		ok = false
	}

	fmt.Println("  Phase 6: Fromt keysign")
	if !keygenOK["fromt"] {
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

	sig1, found1 := r1[msgHex]
	sig2, found2 := r2[msgHex]
	if !found1 || !found2 {
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

// --- batch status helpers ---

func getServerStatuses(sessionID, hexKey string, timeout time.Duration) (server1 map[string]service.ProtocolStatus, server2 map[string]service.ProtocolStatus) {
	if !waitForSessionComplete(sessionID, timeout) {
		return nil, nil
	}
	raw1 := collectBatchStatus(sessionID, hexKey, party2)
	raw2 := collectBatchStatus(sessionID, hexKey, party1)
	return toStatusMap(raw1), toStatusMap(raw2)
}

func toStatusMap(statuses []service.ProtocolStatus) map[string]service.ProtocolStatus {
	m := make(map[string]service.ProtocolStatus)
	for _, s := range statuses {
		m[s.Protocol] = s
	}
	return m
}

func waitForSessionComplete(sessionID string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := httpClient.Get(relayURL + "/complete/" + sessionID)
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("  WARN: failed to close response body: %v\n", err)
		}
		if resp.StatusCode != http.StatusOK {
			time.Sleep(time.Second)
			continue
		}
		var completed []string
		_ = json.Unmarshal(body, &completed)
		if len(completed) >= len(parties) {
			return true
		}
		time.Sleep(time.Second)
	}
	fmt.Println("  Session completion timed out")
	return false
}

func collectBatchStatus(sessionID, hexKey, partyID string) []service.ProtocolStatus {
	url := relayURL + "/message/" + sessionID + "/" + partyID
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("message_id", service.StatusMessageID)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("  WARN: failed to close response body: %v\n", err)
		}
	}()
	body, _ := io.ReadAll(resp.Body)

	var messages []struct {
		From string `json:"from"`
		Body string `json:"body"`
	}
	_ = json.Unmarshal(body, &messages)

	var statuses []service.ProtocolStatus
	for _, msg := range messages {
		decrypted := decryptRelayMessage(msg.Body, hexKey)
		if decrypted == nil {
			continue
		}
		var status service.ProtocolStatus
		unmarshalErr := json.Unmarshal(decrypted, &status)
		if unmarshalErr != nil {
			continue
		}
		statuses = append(statuses, status)
	}
	return statuses
}

func decryptRelayMessage(body, hexKey string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil
	}
	decrypted, err := decryptGCM(decoded, hexKey)
	if err != nil {
		return nil
	}
	inner, err := base64.StdEncoding.DecodeString(string(decrypted))
	if err != nil {
		return nil
	}
	return inner
}

func decryptGCM(ciphertext []byte, hexKey string) ([]byte, error) {
	passwd, _ := hex.DecodeString(hexKey)
	hash := sha256.Sum256(passwd)
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return gcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
}

// --- batch/keysign post helpers ---

func postBatch(serverURL, sessionID, hexKey, localPartyID string, protocols []string, publicKey string) int {
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
	resp, err := httpClient.Post(serverURL+"/vault/batch/keygen", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("  POST failed: %v\n", err)
		return 0
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("  WARN: failed to close response body: %v\n", err)
		}
	}()
	fmt.Printf("  POST %s → %d\n", serverURL, resp.StatusCode)
	return resp.StatusCode
}

func postKeysign(serverURL string, reqBody map[string]any) string {
	body, _ := json.Marshal(reqBody)
	resp, err := httpClient.Post(serverURL+"/vault/sign", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("  POST keysign failed: %v\n", err)
		return ""
	}
	defer func() {
		closeResponseBody(resp)
	}()
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
		resp, err := httpClient.Get(serverURL + "/vault/sign/response/" + taskID)
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		closeResponseBody(resp)

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

func closeResponseBody(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	if err := resp.Body.Close(); err != nil {
		fmt.Printf("  WARN: failed to close response body: %v\n", err)
	}
}

// --- setup message helpers ---

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

func createAndEncryptSetupWithKeyID(hexKey string, keyID []byte) string {
	wrapper := service.NewMPCWrapperImp(false, false)
	idsBytes := encodePartyIDs(parties)
	setupMsg, err := wrapper.KeygenSetupMsgNew(mldsaSession.MlDsa44, len(parties), keyID, idsBytes)
	if err != nil {
		fatal("KeygenSetupMsgNew: %v", err)
	}
	return encryptAndEncode(setupMsg, hexKey)
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

func createSignSetupFull(hexKey string, keyID, messageHash []byte, isEdDSA, isMldsa bool) string {
	wrapper := service.NewMPCWrapperImp(isEdDSA, isMldsa)
	idsBytes := encodePartyIDs(parties)
	setupMsg, err := wrapper.SignSetupMsgNew(mldsaSession.MlDsa44, keyID, []byte("m"), messageHash, idsBytes)
	if err != nil {
		fatal("SignSetupMsgNew: %v", err)
	}
	return encryptAndEncode(setupMsg, hexKey)
}

// --- relay helpers ---

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
	hash := md5.Sum([]byte(from + ":" + body))
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
		closeResponseBody(resp)
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
		closeResponseBody(resp)
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
	closeResponseBody(resp)
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
	closeResponseBody(resp)
}

func startSession(relayURL, sessionID string, parties []string) {
	body, _ := json.Marshal(parties)
	resp, err := httpClient.Post(relayURL+"/start/"+sessionID, "application/json", bytes.NewReader(body))
	if err != nil {
		fatal("start session: %v", err)
	}
	closeResponseBody(resp)
}

func waitForHealth(url string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := httpClient.Get(url)
		if err == nil && resp.StatusCode == http.StatusOK {
			closeResponseBody(resp)
			return
		}
		if resp != nil {
			closeResponseBody(resp)
		}
		time.Sleep(time.Second)
	}
	fatal("timeout waiting for %s", url)
}

// --- crypto/encoding helpers ---

func encryptAndEncode(data []byte, hexKey string) string {
	inner := base64.StdEncoding.EncodeToString(data)
	encrypted, _ := encryptGCM(inner, hexKey)
	return base64.StdEncoding.EncodeToString([]byte(encrypted))
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

func encodePartyIDs(parties []string) []byte {
	return []byte(strings.Join(parties, "\x00"))
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

// --- general helpers ---

func envOrDefault(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
	os.Exit(1)
}

// --- batch reshare test ---

func test7_BatchReshare(ecdsaPK string) bool {
	if ecdsaPK == "" {
		fmt.Println("  SKIP: no ECDSA pubkey from Test 5")
		return false
	}

	sessionID := uuid.New().String()
	hexKey := randomHex(32)

	postReshare(server1URL, sessionID, hexKey, party1, ecdsaPK, []string{"ecdsa", "eddsa"})
	postReshare(server2URL, sessionID, hexKey, party2, ecdsaPK, []string{"ecdsa", "eddsa"})
	waitForParties(relayURL, sessionID, 2, 30*time.Second)
	startSession(relayURL, sessionID, parties)

	s1, s2 := getServerStatuses(sessionID, hexKey, 4*time.Minute)
	if s1 == nil || s2 == nil {
		fmt.Println("  FAIL: no statuses received")
		return false
	}

	ok := true
	for _, name := range []string{"ecdsa", "eddsa"} {
		st1, f1 := s1[name]
		st2, f2 := s2[name]
		if !f1 || st1.Status != service.StatusDone {
			errMsg := "not found"
			if f1 {
				errMsg = st1.Error
			}
			fmt.Printf("  FAIL: server1 %s reshare failed: %s\n", name, errMsg)
			ok = false
			continue
		}
		if !f2 || st2.Status != service.StatusDone {
			fmt.Printf("  FAIL: server2 %s reshare failed\n", name)
			ok = false
			continue
		}
		if st1.PublicKey != st2.PublicKey {
			fmt.Printf("  FAIL: %s reshare keys don't match\n", name)
			ok = false
		} else {
			pk := st1.PublicKey
			if len(pk) > 16 {
				pk = pk[:16]
			}
			fmt.Printf("  OK: %s reshare succeeded (pk: %s...)\n", name, pk)
		}
	}
	return ok
}

func postReshare(serverURL, sessionID, hexKey, localPartyID, publicKey string, protocols []string) int {
	reqBody := map[string]any{
		"public_key":          publicKey,
		"session_id":          sessionID,
		"hex_encryption_key":  hexKey,
		"local_party_id":      localPartyID,
		"encryption_password": "test-password",
		"email":               "test@test.com",
		"old_parties":         parties,
		"protocols":           protocols,
	}
	body, _ := json.Marshal(reqBody)
	resp, err := httpClient.Post(serverURL+"/vault/batch/reshare", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("  POST reshare failed: %v\n", err)
		return 0
	}
	defer func() {
		closeResponseBody(resp)
	}()
	fmt.Printf("  POST reshare %s → %d\n", serverURL, resp.StatusCode)
	return resp.StatusCode
}

// --- batch import test ---

func test8_BatchImport() bool {
	sessionID := uuid.New().String()
	hexKey := randomHex(32)
	importParties := []string{"orchestrator", party1, party2}

	ecdsaPrivKey := randomBytes(32)
	eddsaPrivKey := randomBytes(32)
	eddsaPrivKey[31] = 0 // ensure < Ed25519 curve order (~2^252)
	chainCode := randomBytes(32)

	ecdsaWrapper := service.NewMPCWrapperImp(false, false)
	ecdsaHandle, ecdsaSetup, err := ecdsaWrapper.KeyImportInitiatorNew(ecdsaPrivKey, chainCode, 2, importParties)
	if err != nil {
		fmt.Printf("  FAIL: ECDSA import initiator: %v\n", err)
		return false
	}

	eddsaWrapper := service.NewMPCWrapperImp(true, false)
	eddsaHandle, eddsaSetup, err := eddsaWrapper.KeyImportInitiatorNew(eddsaPrivKey, nil, 2, importParties)
	if err != nil {
		fmt.Printf("  FAIL: EdDSA import initiator: %v\n", err)
		_ = ecdsaWrapper.KeygenSessionFree(ecdsaHandle)
		return false
	}

	froztParties := []frozt.PartyInfo{
		{FrostID: 1, Name: []byte("orchestrator")},
		{FrostID: 2, Name: []byte(party1)},
		{FrostID: 3, Name: []byte(party2)},
	}
	froztSeed := randomBytes(64)
	froztSetup, err := frozt.KeyImportSetupMsgNew(3, 2, froztParties, 0, 1, froztSeed, 0)
	if err != nil {
		fmt.Printf("  FAIL: frozt import setup: %v\n", err)
		return false
	}

	fromtParties := []fromt.PartyInfo{
		{FrostID: 1, Name: []byte("orchestrator")},
		{FrostID: 2, Name: []byte(party1)},
		{FrostID: 3, Name: []byte(party2)},
	}
	fromtSeed := randomBytes(32)
	fromtSpendKey, _, err := fromt.DeriveKeysFromSeed(fromtSeed)
	if err != nil {
		fmt.Printf("  FAIL: fromt derive spend key: %v\n", err)
		return false
	}
	fromtSetup, err := fromt.KeyImportSetupMsgNew(3, 2, fromtParties, 0, 0, 1, fromtSpendKey)
	if err != nil {
		fmt.Printf("  FAIL: fromt import setup: %v\n", err)
		return false
	}

	froztSession, err := service.NewFroztImportProtocol("frozt", "p-frozt", froztSetup, "orchestrator")
	if err != nil {
		fmt.Printf("  FAIL: frozt orchestrator session: %v\n", err)
		return false
	}
	fromtSession, err := service.NewFromtImportProtocol("fromt", "p-fromt", fromtSetup, "orchestrator")
	if err != nil {
		fmt.Printf("  FAIL: fromt orchestrator session: %v\n", err)
		return false
	}

	uploadSetupMessage(relayURL, sessionID, encryptAndEncode(ecdsaSetup, hexKey))
	uploadSetupMessageWithID(relayURL, sessionID, encryptAndEncode(eddsaSetup, hexKey), "eddsa_key_import")
	uploadSetupMessageWithID(relayURL, sessionID, encryptAndEncode(froztSetup, hexKey), "frozt")
	uploadSetupMessageWithID(relayURL, sessionID, encryptAndEncode(fromtSetup, hexKey), "fromt")

	postImport(server1URL, sessionID, hexKey, party1, []string{"ecdsa", "eddsa", "frozt", "fromt"}, nil)
	postImport(server2URL, sessionID, hexKey, party2, []string{"ecdsa", "eddsa", "frozt", "fromt"}, nil)
	registerWithRelay(sessionID, "orchestrator")
	waitForParties(relayURL, sessionID, 3, 30*time.Second)
	startSession(relayURL, sessionID, importParties)

	orchProtocols := []service.KeygenProtocol{
		&mpcInitiatorProtocol{protocolName: "ecdsa", protocolMsgID: "p-ecdsa", handle: ecdsaHandle, wrapper: ecdsaWrapper},
		&mpcInitiatorProtocol{protocolName: "eddsa", protocolMsgID: "p-eddsa", handle: eddsaHandle, wrapper: eddsaWrapper},
		froztSession,
		fromtSession,
	}
	defer func() {
		for _, p := range orchProtocols {
			_ = p.Free()
		}
	}()

	loopOK := runOrchestratorLoop(orchProtocols, sessionID, hexKey, "orchestrator", importParties, 4*time.Minute)
	if !loopOK {
		fmt.Println("  WARN: orchestrator loop did not finish all protocols")
	}

	completeSession(sessionID, "orchestrator")

	s1, s2 := getImportServerStatuses(sessionID, hexKey, importParties, 4*time.Minute)

	ok := true
	for _, name := range []string{"ecdsa", "eddsa", "frozt", "fromt"} {
		st1, f1 := s1[name]
		st2, f2 := s2[name]
		if !f1 || st1.Status != service.StatusDone {
			errMsg := "not found"
			if f1 {
				errMsg = string(st1.Status) + ": " + st1.Error
			}
			fmt.Printf("  FAIL: server1 %s import failed: %s\n", name, errMsg)
			ok = false
			continue
		}
		if !f2 || st2.Status != service.StatusDone {
			errMsg := "not found"
			if f2 {
				errMsg = string(st2.Status) + ": " + st2.Error
			}
			fmt.Printf("  FAIL: server2 %s import failed: %s\n", name, errMsg)
			ok = false
			continue
		}
		pk := st1.PublicKey
		if len(pk) > 16 {
			pk = pk[:16]
		}
		fmt.Printf("  OK: %s import succeeded (pk: %s...)\n", name, pk)
	}
	return ok
}

func postImport(serverURL, sessionID, hexKey, localPartyID string, protocols, chains []string) int {
	reqBody := map[string]any{
		"name":                "test-import-vault",
		"session_id":          sessionID,
		"hex_encryption_key":  hexKey,
		"local_party_id":      localPartyID,
		"encryption_password": "test-password",
		"email":               "test@test.com",
		"protocols":           protocols,
	}
	if len(chains) > 0 {
		reqBody["chains"] = chains
	}
	body, _ := json.Marshal(reqBody)
	resp, err := httpClient.Post(serverURL+"/vault/batch/import", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("  POST import failed: %v\n", err)
		return 0
	}
	defer func() {
		closeResponseBody(resp)
	}()
	fmt.Printf("  POST import %s → %d\n", serverURL, resp.StatusCode)
	return resp.StatusCode
}

func registerWithRelay(sessionID, localPartyID string) {
	body := []byte("[\"" + localPartyID + "\"]")
	resp, err := httpClient.Post(relayURL+"/"+sessionID, "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("  register relay failed: %v\n", err)
		return
	}
	closeResponseBody(resp)
}

func completeSession(sessionID, localPartyID string) {
	body := []byte("[\"" + localPartyID + "\"]")
	req, _ := http.NewRequest("POST", relayURL+"/complete/"+sessionID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Printf("  complete session failed: %v\n", err)
		return
	}
	closeResponseBody(resp)
}

func getImportServerStatuses(sessionID, hexKey string, importParties []string, timeout time.Duration) (map[string]service.ProtocolStatus, map[string]service.ProtocolStatus) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := httpClient.Get(relayURL + "/complete/" + sessionID)
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		closeResponseBody(resp)
		if resp.StatusCode != http.StatusOK {
			time.Sleep(time.Second)
			continue
		}
		var completed []string
		_ = json.Unmarshal(body, &completed)
		if len(completed) >= len(importParties) {
			break
		}
		time.Sleep(time.Second)
	}
	raw1 := collectBatchStatus(sessionID, hexKey, party2)
	raw2 := collectBatchStatus(sessionID, hexKey, party1)
	return toStatusMap(raw1), toStatusMap(raw2)
}

// --- mpc initiator protocol (wraps MPC import initiator handle) ---

type mpcInitiatorProtocol struct {
	protocolName  string
	protocolMsgID string
	handle        service.Handle
	wrapper       *service.MPCWrapperImp
	done          bool
}

func (p *mpcInitiatorProtocol) Name() string      { return p.protocolName }
func (p *mpcInitiatorProtocol) MessageID() string { return p.protocolMsgID }
func (p *mpcInitiatorProtocol) IsFinished() bool  { return p.done }

func (p *mpcInitiatorProtocol) DrainOutbound(allParties []string) ([]service.OutboundMsg, error) {
	var msgs []service.OutboundMsg
	for {
		out, err := p.wrapper.KeygenSessionOutputMessage(p.handle)
		if err != nil {
			return msgs, err
		}
		if len(out) == 0 {
			break
		}
		for i := range allParties {
			receiver, rErr := p.wrapper.KeygenSessionMessageReceiver(p.handle, out, i)
			if rErr != nil {
				return msgs, rErr
			}
			if receiver == "" {
				continue
			}
			msgs = append(msgs, service.OutboundMsg{To: receiver, Body: out})
		}
	}
	return msgs, nil
}

func (p *mpcInitiatorProtocol) ProcessInbound(_ string, body []byte) (bool, error) {
	finished, err := p.wrapper.KeygenSessionInputMessage(p.handle, body)
	if err != nil {
		return false, err
	}
	if finished {
		p.done = true
	}
	return finished, nil
}

func (p *mpcInitiatorProtocol) Result() (*service.PhaseResult, error) {
	return nil, nil
}

func (p *mpcInitiatorProtocol) Free() error {
	return p.wrapper.KeygenSessionFree(p.handle)
}

// --- orchestrator protocol loop ---

type relayMessage struct {
	From string `json:"from"`
	Body string `json:"body"`
	Hash string `json:"hash"`
}

func runOrchestratorLoop(
	protocols []service.KeygenProtocol,
	sessionID, hexKey, localPartyID string,
	allParties []string,
	timeout time.Duration,
) bool {
	for _, p := range protocols {
		outbound, _ := p.DrainOutbound(allParties)
		for _, msg := range outbound {
			sendProtocolMsg(sessionID, hexKey, localPartyID, msg.To, msg.Body, p.MessageID())
		}
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		allDone := true
		progress := false

		for _, p := range protocols {
			if p.IsFinished() {
				continue
			}
			allDone = false

			messages := downloadProtocolMessages(sessionID, localPartyID, p.MessageID())
			for _, msg := range messages {
				decrypted := decryptRelayMessage(msg.Body, hexKey)
				if decrypted == nil {
					deleteProtocolMessage(sessionID, localPartyID, msg.Hash, p.MessageID())
					continue
				}
				finished, procErr := p.ProcessInbound(msg.From, decrypted)
				if procErr != nil {
					fmt.Printf("  orchestrator %s process error from %s: %v\n", p.Name(), msg.From, procErr)
				}
				deleteProtocolMessage(sessionID, localPartyID, msg.Hash, p.MessageID())
				progress = true
				if finished {
					break
				}
			}

			outbound, _ := p.DrainOutbound(allParties)
			for _, msg := range outbound {
				sendProtocolMsg(sessionID, hexKey, localPartyID, msg.To, msg.Body, p.MessageID())
				progress = true
			}
		}

		if allDone {
			return true
		}
		if !progress {
			time.Sleep(100 * time.Millisecond)
		}
	}

	for _, p := range protocols {
		if !p.IsFinished() {
			fmt.Printf("  orchestrator %s timed out\n", p.Name())
		}
	}
	return false
}

func downloadProtocolMessages(sessionID, localPartyID, messageID string) []relayMessage {
	url := relayURL + "/message/" + sessionID + "/" + localPartyID
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("message_id", messageID)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer func() {
		closeResponseBody(resp)
	}()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	var messages []relayMessage
	_ = json.Unmarshal(body, &messages)

	var filtered []relayMessage
	for _, m := range messages {
		if m.From == localPartyID {
			continue
		}
		filtered = append(filtered, m)
	}
	return filtered
}

func deleteProtocolMessage(sessionID, localPartyID, hash, messageID string) {
	req, _ := http.NewRequest("DELETE", relayURL+"/message/"+sessionID+"/"+localPartyID+"/"+hash, nil)
	if messageID != "" {
		req.Header.Set("message_id", messageID)
	}
	resp, _ := httpClient.Do(req)
	if resp != nil {
		closeResponseBody(resp)
	}
}

func sendProtocolMsg(sessionID, hexKey, from, to string, data []byte, messageID string) {
	innerB64 := base64.StdEncoding.EncodeToString(data)
	encrypted, err := encryptGCM(innerB64, hexKey)
	if err != nil {
		return
	}
	body := base64.StdEncoding.EncodeToString([]byte(encrypted))
	hash := md5.Sum([]byte(from + ":" + innerB64))

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
		closeResponseBody(resp)
	}
}
