package service

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/sirupsen/logrus"
	fromt "github.com/vultisig/frost-zm/go/fromt"
)

type FromtImportProtocol struct {
	name         string
	msgID        string
	session      *fromt.SessionHandle
	finished     bool
	parties      []string
	outBuffer    []OutboundMsg
	cachedResult *PhaseResult
	cachedErr    error
}

func NewFromtImportProtocol(
	name, messageID string,
	setupMsg []byte,
	localPartyID string,
) (*FromtImportProtocol, error) {
	session, err := fromt.KeyImportSessionFromSetup(setupMsg, []byte(localPartyID))
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"setupLen":     len(setupMsg),
			"localPartyID": localPartyID,
			"error":        err,
		}).Error("fromt import: session creation failed")
		return nil, fmt.Errorf("fromt import session: %w", err)
	}
	return &FromtImportProtocol{
		name:    name,
		msgID:   messageID,
		session: session,
	}, nil
}

func (p *FromtImportProtocol) Name() string      { return p.name }
func (p *FromtImportProtocol) MessageID() string { return p.msgID }
func (p *FromtImportProtocol) IsFinished() bool  { return p.finished }

func (p *FromtImportProtocol) DrainOutbound(parties []string) ([]OutboundMsg, error) {
	p.parties = parties
	buffered := p.outBuffer
	p.outBuffer = nil

	if p.finished {
		return buffered, nil
	}

	for {
		msg, err := fromt.KeyImportSessionTakeMsg(p.session)
		if err != nil {
			return buffered, fmt.Errorf("fromt import take msg: %w", err)
		}
		if len(msg) == 0 {
			break
		}
		msgs, err := p.resolveReceivers(msg, parties)
		if err != nil {
			return buffered, err
		}
		buffered = append(buffered, msgs...)
	}
	return buffered, nil
}

func (p *FromtImportProtocol) resolveReceivers(msg []byte, parties []string) ([]OutboundMsg, error) {
	payload := msg[2:]
	var msgs []OutboundMsg
	for i := range parties {
		receiver, err := fromt.KeyImportSessionMsgReceiver(p.session, msg, i)
		if err != nil {
			return nil, fmt.Errorf("fromt import msg receiver: %w", err)
		}
		if len(receiver) == 0 {
			continue
		}
		msgs = append(msgs, OutboundMsg{To: string(receiver), Body: payload})
	}
	return msgs, nil
}

func (p *FromtImportProtocol) ProcessInbound(from string, body []byte) (bool, error) {
	senderID := getFrostIdStatic(from, p.parties)
	if senderID == 0 {
		return false, fmt.Errorf("fromt import: unknown sender %s", from)
	}
	frame := make([]byte, 2+len(body))
	binary.LittleEndian.PutUint16(frame, senderID)
	copy(frame[2:], body)

	finished, err := fromt.KeyImportSessionFeed(p.session, frame)
	if err != nil {
		return false, fmt.Errorf("fromt import feed from %s: %w", from, err)
	}
	if finished {
		drainErr := p.drainRemainingOutbound()
		if drainErr != nil {
			return false, drainErr
		}
		p.finished = true
		return true, nil
	}
	return false, nil
}

func (p *FromtImportProtocol) drainRemainingOutbound() error {
	for {
		msg, err := fromt.KeyImportSessionTakeMsg(p.session)
		if err != nil {
			return fmt.Errorf("fromt import take msg: %w", err)
		}
		if len(msg) == 0 {
			return nil
		}
		msgs, err := p.resolveReceivers(msg, p.parties)
		if err != nil {
			return err
		}
		p.outBuffer = append(p.outBuffer, msgs...)
	}
}

func (p *FromtImportProtocol) Result() (*PhaseResult, error) {
	if p.cachedResult != nil {
		return p.cachedResult, p.cachedErr
	}
	result, err := p.computeResult()
	if err != nil && !p.finished {
		return nil, err
	}
	p.cachedResult, p.cachedErr = result, err
	return p.cachedResult, p.cachedErr
}

func (p *FromtImportProtocol) computeResult() (*PhaseResult, error) {
	if !p.finished {
		return nil, fmt.Errorf("fromt import not finished")
	}

	bundle, err := fromt.KeyImportSessionResult(p.session)
	if err != nil {
		return nil, fmt.Errorf("fromt import result: %w", err)
	}

	pk, err := fromt.KeySharePublicKey(bundle)
	if err != nil {
		return nil, fmt.Errorf("fromt import public key: %w", err)
	}

	return &PhaseResult{
		PublicKey: fmt.Sprintf("%x", pk),
		Keyshare:  base64.StdEncoding.EncodeToString(bundle),
	}, nil
}

func (p *FromtImportProtocol) Free() error {
	return fromt.KeyImportSessionFree(p.session)
}
