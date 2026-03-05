package service

import (
	"os"
	"strconv"
	"time"
)

var KeygenTimeout = getKeygenTimeout()

func getKeygenTimeout() time.Duration {
	if v := os.Getenv("KEYGEN_TIMEOUT_MINUTES"); v != "" {
		if m, err := strconv.Atoi(v); err == nil && m > 0 {
			return time.Duration(m) * time.Minute
		}
	}
	return 3 * time.Minute
}

const (
	PollInterval    = 100 * time.Millisecond
	StatusDone      = "done"
	StatusFailed    = "failed"
	StatusTimeout   = "timeout"
	StatusMessageID = "batch-status"
)

type ProtocolStatus struct {
	Protocol  string `json:"protocol"`
	Status    string `json:"status"`
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
