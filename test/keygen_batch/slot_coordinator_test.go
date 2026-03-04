package keygen_batch_test

import (
	"fmt"
	"testing"
	"time"
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

func runKeygen(protocols []*MockProtocol, parties []string, timeout time.Duration) map[string]error {
	errors := make(map[string]error)
	deadline := time.Now().Add(timeout)

	for _, p := range protocols {
		_, _ = p.DrainOutbound(parties)
	}

	for time.Now().Before(deadline) {
		if allFinished(protocols) {
			return errors
		}

		progress := false
		for _, p := range protocols {
			if p.IsFinished() {
				continue
			}
			finished, err := p.ProcessInbound("peer", []byte("msg"))
			if err != nil {
				errors[p.Name()] = err
				continue
			}
			progress = true
			if finished {
				break
			}
			_, _ = p.DrainOutbound(parties)
		}

		if !progress {
			time.Sleep(PollInterval)
		}
	}
	return errors
}

func TestAllProtocolsFinish(t *testing.T) {
	protocols := []*MockProtocol{
		NewMockProtocol("ecdsa", "p-ecdsa", 1, false),
		NewMockProtocol("eddsa", "p-eddsa", 1, false),
		NewMockProtocol("mldsa", "p-mldsa", 1, false),
	}
	parties := []string{"server", "client"}

	errors := runKeygen(protocols, parties, KeygenTimeout)

	if len(errors) > 0 {
		t.Fatalf("unexpected errors: %v", errors)
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

	errors := runKeygen(protocols, parties, KeygenTimeout)

	if len(errors) > 0 {
		t.Fatalf("unexpected errors: %v", errors)
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

	errors := runKeygen(protocols, parties, KeygenTimeout)

	if !protocols[0].IsFinished() {
		t.Fatal("ecdsa should have finished")
	}
	if !protocols[1].IsFinished() {
		t.Fatal("eddsa should have finished")
	}
	if protocols[2].IsFinished() {
		t.Fatal("mldsa should NOT have finished (it always fails)")
	}
	if errors["mldsa"] == nil {
		t.Fatal("mldsa error should have been captured")
	}
}

func TestFailingProtocolDetected(t *testing.T) {
	protocols := []*MockProtocol{
		NewMockProtocol("ecdsa", "p-ecdsa", 1, true),
		NewMockProtocol("eddsa", "p-eddsa", 1, false),
	}
	parties := []string{"server", "client"}

	errors := runKeygen(protocols, parties, KeygenTimeout)

	if protocols[0].IsFinished() {
		t.Fatal("ecdsa should NOT have finished (it always fails)")
	}
	if errors["ecdsa"] == nil {
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
	errors := runKeygen(protocols, parties, KeygenTimeout)
	elapsed := time.Since(start)

	if len(errors) > 0 {
		t.Fatalf("unexpected errors: %v", errors)
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

	errs := runKeygen(protocols, parties, KeygenTimeout)

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

	if errs["mldsa"] == nil {
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
	for _, name := range names {
		if !known[name] {
			return fmt.Errorf("unknown protocol: %s", name)
		}
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
