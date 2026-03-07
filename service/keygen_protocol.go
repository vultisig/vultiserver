package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/vultisig/vultiserver/relay"
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

type ProtocolExchanger struct {
	RelayClient      *relay.Client
	RelayServer      string
	SessionID        string
	HexEncryptionKey string
	LocalPartyID     string
	Parties          []string
	DecryptFn        func(body string, key string) ([]byte, error)
	SendFn           func(msgID string, msgs []OutboundMsg, sessionID, hexEncryptionKey, localPartyID string, parties []string) error
	NotifyFn         func(protocol string, status StatusKind, errMsg, publicKey string)
	Logger           *logrus.Logger
}

func runProtocolExchange(ctx context.Context, p KeygenProtocol, ex ProtocolExchanger) {
	outbound, err := p.DrainOutbound(ex.Parties)
	ex.Logger.WithFields(logrus.Fields{
		"protocol": p.Name(),
		"msgID":    p.MessageID(),
		"outCount": len(outbound),
		"parties":  ex.Parties,
		"localID":  ex.LocalPartyID,
	}).Info("protocol exchange started")
	if len(outbound) > 0 {
		sendErr := ex.SendFn(p.MessageID(), outbound, ex.SessionID, ex.HexEncryptionKey, ex.LocalPartyID, ex.Parties)
		if sendErr != nil {
			ex.Logger.WithFields(logrus.Fields{
				"protocol": p.Name(),
				"error":    sendErr,
			}).Warn("initial send outbound failed")
		}
	}
	if err != nil {
		ex.Logger.WithFields(logrus.Fields{
			"protocol": p.Name(),
			"error":    err,
		}).Error("initial drain outbound failed")
	}

	failedNotified := false

	for {
		select {
		case <-ctx.Done():
			if !p.IsFinished() && !failedNotified {
				ex.NotifyFn(p.Name(), StatusTimeout, "", "")
			}
			return
		default:
		}

		if p.IsFinished() {
			return
		}

		progress := false
		messages, dlErr := ex.RelayClient.DownloadMessages(ex.SessionID, ex.LocalPartyID, p.MessageID())
		if dlErr != nil {
			time.Sleep(PollInterval)
			continue
		}

		for _, msg := range messages {
			if msg.From == ex.LocalPartyID {
				continue
			}
			body, decErr := ex.DecryptFn(msg.Body, ex.HexEncryptionKey)
			if decErr != nil {
				ex.Logger.WithFields(logrus.Fields{
					"protocol": p.Name(),
					"from":     msg.From,
					"error":    decErr,
				}).Warn("decrypt inbound failed")
				_ = ex.RelayClient.DeleteMessageFromServer(ex.SessionID, ex.LocalPartyID, msg.Hash, p.MessageID())
				continue
			}
			ex.Logger.WithFields(logrus.Fields{
				"protocol": p.Name(),
				"from":     msg.From,
				"bodyLen":  len(body),
			}).Debug("processing inbound message")
			finished, procErr := p.ProcessInbound(msg.From, body)
			if procErr != nil {
				ex.Logger.WithFields(logrus.Fields{
					"protocol": p.Name(),
					"from":     msg.From,
					"error":    procErr,
				}).Warn("process inbound failed")
				if !failedNotified {
					ex.NotifyFn(p.Name(), StatusFailed, procErr.Error(), "")
					failedNotified = true
				}
			}
			_ = ex.RelayClient.DeleteMessageFromServer(ex.SessionID, ex.LocalPartyID, msg.Hash, p.MessageID())
			progress = true
			if finished {
				finalOutbound, finalDrainErr := p.DrainOutbound(ex.Parties)
				if len(finalOutbound) > 0 {
					sendErr := ex.SendFn(p.MessageID(), finalOutbound, ex.SessionID, ex.HexEncryptionKey, ex.LocalPartyID, ex.Parties)
					if sendErr != nil {
						ex.Logger.WithFields(logrus.Fields{"protocol": p.Name(), "error": sendErr}).Warn("send final outbound failed")
					}
				}
				if finalDrainErr != nil {
					ex.Logger.WithFields(logrus.Fields{"protocol": p.Name(), "error": finalDrainErr}).Warn("drain final outbound failed")
				}

				publicKey := ""
				pr, resultErr := p.Result()
				if resultErr == nil {
					publicKey = pr.PublicKey
				}
				ex.Logger.WithFields(logrus.Fields{
					"protocol":  p.Name(),
					"publicKey": publicKey,
				}).Info("protocol finished")
				ex.NotifyFn(p.Name(), StatusDone, "", publicKey)
				return
			}
		}

		newOutbound, drainErr := p.DrainOutbound(ex.Parties)
		if len(newOutbound) > 0 {
			ex.Logger.WithFields(logrus.Fields{
				"protocol": p.Name(),
				"outCount": len(newOutbound),
			}).Info("sending outbound after processing")
			sendErr := ex.SendFn(p.MessageID(), newOutbound, ex.SessionID, ex.HexEncryptionKey, ex.LocalPartyID, ex.Parties)
			if sendErr != nil {
				ex.Logger.WithFields(logrus.Fields{"protocol": p.Name(), "error": sendErr}).Warn("send outbound failed")
			} else {
				progress = true
			}
		}
		if drainErr != nil {
			ex.Logger.WithFields(logrus.Fields{"protocol": p.Name(), "error": drainErr}).Warn("drain outbound failed")
		}

		if !progress {
			time.Sleep(PollInterval)
		}
	}
}

func notifyStatusViaRelay(
	sendFn func(msgID string, msgs []OutboundMsg, sessionID, hexEncryptionKey, localPartyID string, parties []string) error,
	sessionID, hexEncryptionKey, localPartyID string,
	parties []string,
	logger *logrus.Logger,
) func(protocol string, status StatusKind, errMsg, publicKey string) {
	return func(protocol string, status StatusKind, errMsg, publicKey string) {
		msg := ProtocolStatus{
			Protocol:  protocol,
			Status:    status,
			Error:     errMsg,
			PublicKey: publicKey,
		}
		body, err := json.Marshal(msg)
		if err != nil {
			logger.WithFields(logrus.Fields{"protocol": protocol, "error": err}).Warn("failed to marshal status")
			return
		}
		sendErr := sendFn(StatusMessageID, []OutboundMsg{{Body: body}}, sessionID, hexEncryptionKey, localPartyID, parties)
		if sendErr != nil {
			logger.WithFields(logrus.Fields{"protocol": protocol, "status": status, "error": sendErr}).Warn("failed to send status notification")
		}
	}
}

func encryptAndSendMessages(
	relayServer, sessionID, hexEncryptionKey string, encrypt bool, messageID string,
	messages []OutboundMsg,
	localPartyID string, parties []string,
) error {
	messenger := relay.NewMessenger(relayServer, sessionID, hexEncryptionKey, encrypt, messageID)
	for _, msg := range messages {
		body := base64.StdEncoding.EncodeToString(msg.Body)
		if msg.To == "" {
			for _, peer := range parties {
				if peer == localPartyID {
					continue
				}
				sendErr := messenger.Send(localPartyID, peer, body)
				if sendErr != nil {
					return sendErr
				}
			}
		} else {
			sendErr := messenger.Send(localPartyID, msg.To, body)
			if sendErr != nil {
				return sendErr
			}
		}
	}
	return nil
}
