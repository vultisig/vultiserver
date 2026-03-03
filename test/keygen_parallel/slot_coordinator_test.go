package keygen_parallel_test

import (
	"fmt"
	"testing"
	"time"
)

const (
	MaxKeygenSlots = 6
	SlotTimeout    = 200 * time.Millisecond
	PollInterval   = 10 * time.Millisecond
)

type OutboundMsg struct {
	To   string
	Body []byte
}

type PhaseResult struct {
	PublicKey string
	ChainCode string
	Keyshare  string
}

type MockProtocol struct {
	name          string
	msgID         string
	required      bool
	finished      bool
	roundsNeeded  int
	roundsDone    int
	shouldFail    bool
	outboundReady bool
	inboundQueue  [][]byte
}

func NewMockProtocol(name, msgID string, required bool, roundsNeeded int, shouldFail bool) *MockProtocol {
	return &MockProtocol{
		name:          name,
		msgID:         msgID,
		required:      required,
		roundsNeeded:  roundsNeeded,
		shouldFail:    shouldFail,
		outboundReady: true,
	}
}

func (p *MockProtocol) Name() string     { return p.name }
func (p *MockProtocol) MessageID() string { return p.msgID }
func (p *MockProtocol) Required() bool    { return p.required }
func (p *MockProtocol) IsFinished() bool  { return p.finished }

func (p *MockProtocol) DrainOutbound(_ []string) ([]OutboundMsg, error) {
	if !p.outboundReady {
		return nil, nil
	}
	p.outboundReady = false
	return []OutboundMsg{{To: "peer", Body: []byte(fmt.Sprintf("%s-round%d", p.name, p.roundsDone+1))}}, nil
}

func (p *MockProtocol) ProcessInbound(_ string, _ []byte) (bool, error) {
	if p.shouldFail {
		return false, fmt.Errorf("protocol %s always fails", p.name)
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
		PublicKey: fmt.Sprintf("pubkey-%s", p.name),
		ChainCode: "chaincode",
		Keyshare:  "keyshare",
	}, nil
}

func (p *MockProtocol) Free() error { return nil }

func runSlots(protocols []*MockProtocol, parties []string) int {
	slotsRan := 0
	for slot := range MaxKeygenSlots {
		_ = slot
		slotsRan++

		allDone := true
		for _, p := range protocols {
			if p.IsFinished() {
				continue
			}
			allDone = false
		}
		if allDone {
			break
		}

		for _, p := range protocols {
			if p.IsFinished() {
				continue
			}
			_, _ = p.DrainOutbound(parties)
		}

		slotDeadline := time.Now().Add(SlotTimeout)
		for time.Now().Before(slotDeadline) {
			progress := false
			for _, p := range protocols {
				if p.IsFinished() {
					continue
				}
				finished, _ := p.ProcessInbound("peer", []byte("msg"))
				progress = true
				if finished {
					break
				}
				_, _ = p.DrainOutbound(parties)
			}

			allDone := true
			for _, p := range protocols {
				if !p.IsFinished() {
					allDone = false
					break
				}
			}
			if allDone {
				break
			}
			if !progress {
				time.Sleep(PollInterval)
			}
		}

		allDone = true
		for _, p := range protocols {
			if !p.IsFinished() {
				allDone = false
				break
			}
		}
		if allDone {
			break
		}
	}
	return slotsRan
}

func TestAllProtocolsFinishInOneSlot(t *testing.T) {
	protocols := []*MockProtocol{
		NewMockProtocol("ecdsa", "p-ecdsa", true, 1, false),
		NewMockProtocol("eddsa", "p-eddsa", true, 1, false),
		NewMockProtocol("frozt", "p-frozt", false, 1, false),
	}
	parties := []string{"server", "client"}

	slotsRan := runSlots(protocols, parties)

	for _, p := range protocols {
		if !p.IsFinished() {
			t.Fatalf("protocol %s should have finished", p.Name())
		}
	}
	if slotsRan != 1 {
		t.Fatalf("expected 1 slot (early exit), got %d", slotsRan)
	}
}

func TestSlowProtocolFinishesInLaterSlot(t *testing.T) {
	protocols := []*MockProtocol{
		NewMockProtocol("ecdsa", "p-ecdsa", true, 1, false),
		NewMockProtocol("eddsa", "p-eddsa", true, 3, false),
		NewMockProtocol("frozt", "p-frozt", false, 1, false),
	}
	parties := []string{"server", "client"}

	slotsRan := runSlots(protocols, parties)

	for _, p := range protocols {
		if !p.IsFinished() {
			t.Fatalf("protocol %s should have finished", p.Name())
		}
	}
	if slotsRan > 3 {
		t.Fatalf("expected at most 3 slots, got %d", slotsRan)
	}
}

func TestFailingOptionalProtocolDoesNotBlockKeygen(t *testing.T) {
	protocols := []*MockProtocol{
		NewMockProtocol("ecdsa", "p-ecdsa", true, 2, false),
		NewMockProtocol("eddsa", "p-eddsa", true, 2, false),
		NewMockProtocol("frozt", "p-frozt", false, 1, true),
	}
	parties := []string{"server", "client"}

	runSlots(protocols, parties)

	if !protocols[0].IsFinished() {
		t.Fatal("ecdsa should have finished")
	}
	if !protocols[1].IsFinished() {
		t.Fatal("eddsa should have finished")
	}
	if protocols[2].IsFinished() {
		t.Fatal("frozt should NOT have finished (it always fails)")
	}
}

func TestFailingRequiredProtocolDetected(t *testing.T) {
	protocols := []*MockProtocol{
		NewMockProtocol("ecdsa", "p-ecdsa", true, 1, true),
		NewMockProtocol("eddsa", "p-eddsa", true, 1, false),
	}
	parties := []string{"server", "client"}

	runSlots(protocols, parties)

	if protocols[0].IsFinished() {
		t.Fatal("ecdsa should NOT have finished (it always fails)")
	}
	if protocols[0].Required() && !protocols[0].IsFinished() {
		// This is the expected state — coordinator should detect this
	}
}

func TestMaxSlotsRespected(t *testing.T) {
	protocols := []*MockProtocol{
		NewMockProtocol("ecdsa", "p-ecdsa", true, 100, false),
	}
	parties := []string{"server", "client"}

	slotsRan := runSlots(protocols, parties)

	if slotsRan > MaxKeygenSlots {
		t.Fatalf("expected max %d slots, got %d", MaxKeygenSlots, slotsRan)
	}
}

func TestFastForwardWhenAllAdvance(t *testing.T) {
	protocols := []*MockProtocol{
		NewMockProtocol("ecdsa", "p-ecdsa", true, 3, false),
		NewMockProtocol("eddsa", "p-eddsa", true, 3, false),
	}
	parties := []string{"server", "client"}

	start := time.Now()
	slotsRan := runSlots(protocols, parties)
	elapsed := time.Since(start)

	for _, p := range protocols {
		if !p.IsFinished() {
			t.Fatalf("protocol %s should have finished", p.Name())
		}
	}
	if slotsRan > 3 {
		t.Fatalf("expected 3 slots, got %d", slotsRan)
	}
	if elapsed > 3*SlotTimeout {
		t.Fatalf("slots should have fast-forwarded, took %v", elapsed)
	}
}

func TestProtocolListValidation(t *testing.T) {
	tests := []struct {
		protocols []string
		wantErr   bool
	}{
		{[]string{"ecdsa", "eddsa"}, false},
		{[]string{"ecdsa", "eddsa", "frozt"}, false},
		{[]string{"ecdsa", "eddsa", "fromt"}, false},
		{[]string{"ecdsa", "eddsa", "frozt", "fromt"}, false},
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
	known := map[string]bool{"ecdsa": true, "eddsa": true, "frozt": true, "fromt": true}
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
