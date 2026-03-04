package service

import (
	"time"
)

const (
	MaxKeygenSlots = 6
	SlotTimeout    = 2 * time.Second
	PollInterval   = 100 * time.Millisecond
)

type OutboundMsg struct {
	To   string // target party ("" = broadcast to all peers)
	Body []byte
}

type PhaseResult struct {
	PublicKey string
	ChainCode string
	Keyshare  string
}

type KeygenPhaseStatus struct {
	Name      string `json:"name"`
	Success   bool   `json:"success"`
	Skipped   bool   `json:"skipped,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
	Error     string `json:"error,omitempty"`
}

type KeygenResult struct {
	ECDSAPublicKey string
	EDDSAPublicKey string
	Phases         []KeygenPhaseStatus
	phaseResults   map[string]*PhaseResult
}

type KeygenProtocol interface {
	Name() string
	MessageID() string
	IsFinished() bool
	DrainOutbound(parties []string) ([]OutboundMsg, error)
	ProcessInbound(from string, body []byte) (finished bool, err error)
	Result() (*PhaseResult, error)
	Free() error
}
