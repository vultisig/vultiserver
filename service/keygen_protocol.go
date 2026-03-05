package service

import (
	"log"
	"os"
	"strconv"
	"time"
)

var KeygenTimeout = getKeygenTimeout()

func getKeygenTimeout() time.Duration {
	v := os.Getenv("KEYGEN_TIMEOUT_MINUTES")
	if v == "" {
		return 3 * time.Minute
	}
	m, err := strconv.Atoi(v)
	if err != nil || m <= 0 {
		log.Printf("invalid KEYGEN_TIMEOUT_MINUTES=%q, using default 3m", v)
		return 3 * time.Minute
	}
	return time.Duration(m) * time.Minute
}

const PollInterval = 100 * time.Millisecond

type StatusKind string

const (
	StatusDone    StatusKind = "done"
	StatusFailed  StatusKind = "failed"
	StatusTimeout StatusKind = "timeout"
)

const StatusMessageID = "batch-status"

type ProtocolStatus struct {
	Protocol  string     `json:"protocol"`
	Status    StatusKind `json:"status"`
	Error     string `json:"error,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
}

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
	MLDSAPublicKey string
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
