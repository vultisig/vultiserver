package keygen_batch_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

type ProtocolStatus struct {
	Protocol string `json:"protocol"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
}

const (
	StatusDone    = "done"
	StatusFailed  = "failed"
	StatusTimeout = "timeout"
)

const (
	KeygenTimeout = 200 * time.Millisecond
	PollInterval  = 10 * time.Millisecond
)

type OutboundMsg struct {
	To   string
	Body []byte
}

type PhaseResult struct {
	PublicKey  string
	ChainCode string
	Keyshare  string
}

type MockProtocol struct {
	name          string
	msgID         string
	finished      bool
	roundsNeeded  int
	roundsDone    int
	shouldFail    bool
	stalled       bool
	outboundReady bool
	failedErr     error
}

func NewMockProtocol(name, msgID string, roundsNeeded int, shouldFail bool) *MockProtocol {
	return &MockProtocol{
		name:          name,
		msgID:         msgID,
		roundsNeeded:  roundsNeeded,
		shouldFail:    shouldFail,
		outboundReady: true,
	}
}

func (p *MockProtocol) Name() string     { return p.name }
func (p *MockProtocol) MessageID() string { return p.msgID }
func (p *MockProtocol) IsFinished() bool  { return p.finished }

func (p *MockProtocol) DrainOutbound(_ []string) ([]OutboundMsg, error) {
	if !p.outboundReady {
		return nil, nil
	}
	p.outboundReady = false
	return []OutboundMsg{{To: "peer", Body: fmt.Appendf(nil, "%s-round%d", p.name, p.roundsDone+1)}}, nil
}

func (p *MockProtocol) ProcessInbound(_ string, _ []byte) (bool, error) {
	if p.stalled {
		return false, nil
	}
	if p.shouldFail {
		err := fmt.Errorf("protocol %s always fails", p.name)
		p.failedErr = err
		return false, err
	}
	p.roundsDone++
	p.outboundReady = true
	if p.roundsDone >= p.roundsNeeded {
		p.finished = true
		return true, nil
	}
	return false, nil
}

func (p *MockProtocol) Result() (*PhaseResult, error) {
	if !p.finished {
		return nil, fmt.Errorf("not finished")
	}
	return &PhaseResult{
		PublicKey:  fmt.Sprintf("pubkey-%s", p.name),
		ChainCode: "chaincode",
		Keyshare:  "keyshare",
	}, nil
}

func (p *MockProtocol) Free() error { return nil }

func allFinished(protocols []*MockProtocol) bool {
	for _, p := range protocols {
		if !p.IsFinished() {
			return false
		}
	}
	return true
}

type runKeygenResult struct {
	errors        map[string]error
	notifications []ProtocolStatus
}

func runKeygen(protocols []*MockProtocol, parties []string, timeout time.Duration) runKeygenResult {
	result := runKeygenResult{
		errors: make(map[string]error),
	}
	deadline := time.Now().Add(timeout)
	failedNotified := make(map[string]bool)

	notify := func(protocol, status, errMsg string) {
		result.notifications = append(result.notifications, ProtocolStatus{
			Protocol: protocol,
			Status:   status,
			Error:    errMsg,
		})
	}

	for _, p := range protocols {
		_, _ = p.DrainOutbound(parties)
	}

	for time.Now().Before(deadline) {
		if allFinished(protocols) {
			return result
		}

		progress := false
		for _, p := range protocols {
			if p.IsFinished() {
				continue
			}
			finished, err := p.ProcessInbound("peer", []byte("msg"))
			if err != nil {
				result.errors[p.Name()] = err
				if !failedNotified[p.Name()] {
					notify(p.Name(), StatusFailed, err.Error())
					failedNotified[p.Name()] = true
				}
				continue
			}
			progress = true
			if finished {
				notify(p.Name(), StatusDone, "")
				break
			}
			_, _ = p.DrainOutbound(parties)
		}

		if !progress {
			time.Sleep(PollInterval)
		}
	}

	for _, p := range protocols {
		if !p.IsFinished() && !failedNotified[p.Name()] {
			notify(p.Name(), StatusTimeout, "")
		}
	}

	return result
}

func TestAllProtocolsFinish(t *testing.T) {
	protocols := []*MockProtocol{
		NewMockProtocol("ecdsa", "p-ecdsa", 1, false),
		NewMockProtocol("eddsa", "p-eddsa", 1, false),
		NewMockProtocol("mldsa", "p-mldsa", 1, false),
	}
	parties := []string{"server", "client"}

	result := runKeygen(protocols, parties, KeygenTimeout)

	if len(result.errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.errors)
	}
	for _, p := range protocols {
		if !p.IsFinished() {
			t.Fatalf("protocol %s should have finished", p.Name())
		}
	}
}

func TestMultiRoundProtocolFinishes(t *testing.T) {
	protocols := []*MockProtocol{
		NewMockProtocol("ecdsa", "p-ecdsa", 1, false),
		NewMockProtocol("eddsa", "p-eddsa", 3, false),
		NewMockProtocol("mldsa", "p-mldsa", 2, false),
	}
	parties := []string{"server", "client"}

	result := runKeygen(protocols, parties, KeygenTimeout)

	if len(result.errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.errors)
	}
	for _, p := range protocols {
		if !p.IsFinished() {
			t.Fatalf("protocol %s should have finished", p.Name())
		}
	}
}

func TestFailingOptionalProtocolDoesNotBlock(t *testing.T) {
	protocols := []*MockProtocol{
		NewMockProtocol("ecdsa", "p-ecdsa", 2, false),
		NewMockProtocol("eddsa", "p-eddsa", 2, false),
		NewMockProtocol("mldsa", "p-mldsa", 1, true),
	}
	parties := []string{"server", "client"}

	result := runKeygen(protocols, parties, KeygenTimeout)

	if !protocols[0].IsFinished() {
		t.Fatal("ecdsa should have finished")
	}
	if !protocols[1].IsFinished() {
		t.Fatal("eddsa should have finished")
	}
	if protocols[2].IsFinished() {
		t.Fatal("mldsa should NOT have finished (it always fails)")
	}
	if result.errors["mldsa"] == nil {
		t.Fatal("mldsa error should have been captured")
	}
}

func TestFailingProtocolDetected(t *testing.T) {
	protocols := []*MockProtocol{
		NewMockProtocol("ecdsa", "p-ecdsa", 1, true),
		NewMockProtocol("eddsa", "p-eddsa", 1, false),
	}
	parties := []string{"server", "client"}

	result := runKeygen(protocols, parties, KeygenTimeout)

	if protocols[0].IsFinished() {
		t.Fatal("ecdsa should NOT have finished (it always fails)")
	}
	if result.errors["ecdsa"] == nil {
		t.Fatal("ecdsa failure should have been detected")
	}
}

func TestTimeoutRespected(t *testing.T) {
	p := NewMockProtocol("ecdsa", "p-ecdsa", 10000, false)
	p.stalled = true
	protocols := []*MockProtocol{p}
	parties := []string{"server", "client"}

	timeout := 100 * time.Millisecond
	start := time.Now()
	_ = runKeygen(protocols, parties, timeout)
	elapsed := time.Since(start)

	if protocols[0].IsFinished() {
		t.Fatal("protocol should NOT have finished within timeout")
	}
	if elapsed > 2*timeout {
		t.Fatalf("should have stopped near timeout, took %v", elapsed)
	}
}

func TestEarlyExitWhenAllDone(t *testing.T) {
	protocols := []*MockProtocol{
		NewMockProtocol("ecdsa", "p-ecdsa", 1, false),
		NewMockProtocol("eddsa", "p-eddsa", 1, false),
	}
	parties := []string{"server", "client"}

	start := time.Now()
	result := runKeygen(protocols, parties, KeygenTimeout)
	elapsed := time.Since(start)

	if len(result.errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.errors)
	}
	for _, p := range protocols {
		if !p.IsFinished() {
			t.Fatalf("protocol %s should have finished", p.Name())
		}
	}
	if elapsed > KeygenTimeout/2 {
		t.Fatalf("should have exited early, took %v", elapsed)
	}
}

func TestResultsMatchAfterKeygen(t *testing.T) {
	protocols := []*MockProtocol{
		NewMockProtocol("ecdsa", "p-ecdsa", 1, false),
		NewMockProtocol("eddsa", "p-eddsa", 2, false),
		NewMockProtocol("mldsa", "p-mldsa", 1, true),
	}
	parties := []string{"server", "client"}

	result := runKeygen(protocols, parties, KeygenTimeout)

	results := make(map[string]*PhaseResult)
	for _, p := range protocols {
		res, err := p.Result()
		if p.shouldFail {
			if err == nil {
				t.Fatalf("expected Result() error for failed protocol %s", p.Name())
			}
			continue
		}
		if err != nil {
			t.Fatalf("Result() error for %s: %v", p.Name(), err)
		}
		results[p.Name()] = res
	}

	if result.errors["mldsa"] == nil {
		t.Fatal("mldsa error should have been captured")
	}
	if _, ok := results["mldsa"]; ok {
		t.Fatal("mldsa should not have a result")
	}

	for _, name := range []string{"ecdsa", "eddsa"} {
		res, ok := results[name]
		if !ok {
			t.Fatalf("missing result for %s", name)
		}
		expected := fmt.Sprintf("pubkey-%s", name)
		if res.PublicKey != expected {
			t.Fatalf("%s public key = %q, want %q", name, res.PublicKey, expected)
		}
		if res.ChainCode == "" {
			t.Fatalf("%s chain code is empty", name)
		}
		if res.Keyshare == "" {
			t.Fatalf("%s keyshare is empty", name)
		}
	}

	if results["ecdsa"].PublicKey == results["eddsa"].PublicKey {
		t.Fatal("ecdsa and eddsa should have distinct public keys")
	}
}

func TestNotifyDoneOnSuccess(t *testing.T) {
	protocols := []*MockProtocol{
		NewMockProtocol("ecdsa", "p-ecdsa", 1, false),
		NewMockProtocol("eddsa", "p-eddsa", 1, false),
	}
	parties := []string{"server", "client"}

	result := runKeygen(protocols, parties, KeygenTimeout)

	if len(result.errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.errors)
	}

	doneCount := 0
	for _, n := range result.notifications {
		if n.Status != StatusDone {
			t.Fatalf("expected only done notifications, got %s for %s", n.Status, n.Protocol)
		}
		doneCount++
	}
	if doneCount != 2 {
		t.Fatalf("expected 2 done notifications, got %d", doneCount)
	}
}

func TestNotifyFailedOnError(t *testing.T) {
	protocols := []*MockProtocol{
		NewMockProtocol("ecdsa", "p-ecdsa", 2, false),
		NewMockProtocol("eddsa", "p-eddsa", 2, false),
		NewMockProtocol("mldsa", "p-mldsa", 1, true),
	}
	parties := []string{"server", "client"}

	result := runKeygen(protocols, parties, KeygenTimeout)

	failedNotifications := 0
	for _, n := range result.notifications {
		if n.Protocol == "mldsa" && n.Status == StatusFailed {
			failedNotifications++
			if n.Error == "" {
				t.Fatal("failed notification should include error message")
			}
		}
	}
	if failedNotifications != 1 {
		t.Fatalf("expected exactly 1 failed notification for mldsa, got %d", failedNotifications)
	}
}

func TestNotifyFailedOnlyOnce(t *testing.T) {
	protocols := []*MockProtocol{
		NewMockProtocol("ecdsa", "p-ecdsa", 1, true),
		NewMockProtocol("eddsa", "p-eddsa", 1, false),
	}
	parties := []string{"server", "client"}

	result := runKeygen(protocols, parties, KeygenTimeout)

	failedCount := 0
	for _, n := range result.notifications {
		if n.Protocol == "ecdsa" && n.Status == StatusFailed {
			failedCount++
		}
	}
	if failedCount != 1 {
		t.Fatalf("expected exactly 1 failed notification for ecdsa (not repeated), got %d", failedCount)
	}
}

func TestNotifyTimeoutOnStall(t *testing.T) {
	p := NewMockProtocol("ecdsa", "p-ecdsa", 10000, false)
	p.stalled = true
	protocols := []*MockProtocol{p}
	parties := []string{"server", "client"}

	result := runKeygen(protocols, parties, 100*time.Millisecond)

	timeoutCount := 0
	for _, n := range result.notifications {
		if n.Protocol == "ecdsa" && n.Status == StatusTimeout {
			timeoutCount++
		}
	}
	if timeoutCount != 1 {
		t.Fatalf("expected 1 timeout notification for stalled protocol, got %d", timeoutCount)
	}
}

func TestNotifyMixedStatuses(t *testing.T) {
	stalled := NewMockProtocol("eddsa", "p-eddsa", 10000, false)
	stalled.stalled = true
	protocols := []*MockProtocol{
		NewMockProtocol("ecdsa", "p-ecdsa", 1, false),
		stalled,
		NewMockProtocol("mldsa", "p-mldsa", 1, true),
	}
	parties := []string{"server", "client"}

	result := runKeygen(protocols, parties, KeygenTimeout)

	statusMap := make(map[string]string)
	for _, n := range result.notifications {
		statusMap[n.Protocol] = n.Status
	}
	if statusMap["ecdsa"] != StatusDone {
		t.Fatalf("ecdsa should be done, got %q", statusMap["ecdsa"])
	}
	if statusMap["mldsa"] != StatusFailed {
		t.Fatalf("mldsa should be failed, got %q", statusMap["mldsa"])
	}
	if statusMap["eddsa"] != StatusTimeout {
		t.Fatalf("eddsa should be timeout, got %q", statusMap["eddsa"])
	}
}

func TestNotificationSerializesToJSON(t *testing.T) {
	status := ProtocolStatus{Protocol: "ecdsa", Status: StatusDone}
	data, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded ProtocolStatus
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if decoded.Protocol != "ecdsa" || decoded.Status != StatusDone {
		t.Fatalf("round-trip mismatch: %+v", decoded)
	}

	statusWithErr := ProtocolStatus{Protocol: "mldsa", Status: StatusFailed, Error: "some error"}
	data, _ = json.Marshal(statusWithErr)
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if decoded.Error != "some error" {
		t.Fatalf("error field mismatch: %q", decoded.Error)
	}
}

func TestProtocolListValidation(t *testing.T) {
	tests := []struct {
		protocols []string
		wantErr   bool
	}{
		{[]string{"ecdsa", "eddsa"}, false},
		{[]string{"ecdsa", "eddsa", "mldsa"}, false},
		{[]string{"ecdsa"}, true},
		{[]string{"eddsa"}, true},
		{[]string{}, true},
		{[]string{"ecdsa", "eddsa", "unknown"}, true},
		{[]string{"ecdsa", "eddsa", "ecdsa"}, true},
	}

	for _, tt := range tests {
		err := validateProtocolList(tt.protocols)
		if (err != nil) != tt.wantErr {
			t.Errorf("validateProtocolList(%v) error = %v, wantErr %v", tt.protocols, err, tt.wantErr)
		}
	}
}

func validateProtocolList(names []string) error {
	known := map[string]bool{"ecdsa": true, "eddsa": true, "mldsa": true}
	hasECDSA := false
	hasEdDSA := false
	seen := map[string]bool{}
	for _, name := range names {
		if !known[name] {
			return fmt.Errorf("unknown protocol: %s", name)
		}
		if seen[name] {
			return fmt.Errorf("duplicate protocol: %s", name)
		}
		seen[name] = true
		if name == "ecdsa" {
			hasECDSA = true
		}
		if name == "eddsa" {
			hasEdDSA = true
		}
	}
	if !hasECDSA {
		return fmt.Errorf("ecdsa is required")
	}
	if !hasEdDSA {
		return fmt.Errorf("eddsa is required")
	}
	return nil
}
