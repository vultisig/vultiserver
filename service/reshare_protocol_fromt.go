package service

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"

	fromt "github.com/vultisig/frost-zm/go/fromt"
)

type FromtReshareProtocol struct {
	name         string
	msgID        string
	session      *fromt.SessionHandle
	finished     bool
	parties      []string
	outBuffer    []OutboundMsg
	cachedResult *PhaseResult
	cachedErr    error
}

func NewFromtReshareProtocol(
	name, messageID string,
	setupMsg []byte,
	localPartyID string,
	oldKeyShare []byte,
) (*FromtReshareProtocol, error) {
	session, err := fromt.ReshareSessionFromSetup(setupMsg, []byte(localPartyID), oldKeyShare)
	if err != nil {
		return nil, fmt.Errorf("fromt reshare session: %w", err)
	}

	return &FromtReshareProtocol{
		name:    name,
		msgID:   messageID,
		session: session,
	}, nil
}

func (p *FromtReshareProtocol) Name() string     { return p.name }
func (p *FromtReshareProtocol) MessageID() string { return p.msgID }
func (p *FromtReshareProtocol) IsFinished() bool  { return p.finished }

func (p *FromtReshareProtocol) DrainOutbound(parties []string) ([]OutboundMsg, error) {
	p.parties = parties
	buffered := p.outBuffer
	p.outBuffer = nil

	if p.finished {
		return buffered, nil
	}

	for {
		msg, err := fromt.ReshareSessionTakeMsg(p.session)
		if err != nil {
			return buffered, fmt.Errorf("fromt reshare take msg: %w", err)
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

func (p *FromtReshareProtocol) resolveReceivers(msg []byte, parties []string) ([]OutboundMsg, error) {
	payload := msg[2:]
	var msgs []OutboundMsg
	for i := range parties {
		receiver, err := fromt.ReshareSessionMsgReceiver(p.session, msg, i)
		if err != nil {
			return nil, fmt.Errorf("fromt reshare msg receiver: %w", err)
		}
		if len(receiver) == 0 {
			continue
		}
		msgs = append(msgs, OutboundMsg{To: string(receiver), Body: payload})
	}
	return msgs, nil
}

func (p *FromtReshareProtocol) ProcessInbound(from string, body []byte) (bool, error) {
	senderID := getFrostIdStatic(from, p.parties)
	if senderID == 0 {
		return false, fmt.Errorf("fromt reshare: unknown sender %s", from)
	}
	frame := make([]byte, 2+len(body))
	binary.LittleEndian.PutUint16(frame, senderID)
	copy(frame[2:], body)

	finished, err := fromt.ReshareSessionFeed(p.session, frame)
	if err != nil {
		return false, fmt.Errorf("fromt reshare feed from %s: %w", from, err)
	}
	if finished {
		p.drainRemainingOutbound()
		p.finished = true
		return true, nil
	}
	return false, nil
}

func (p *FromtReshareProtocol) drainRemainingOutbound() {
	for {
		msg, err := fromt.ReshareSessionTakeMsg(p.session)
		if err != nil || len(msg) == 0 {
			break
		}
		msgs, err := p.resolveReceivers(msg, p.parties)
		if err != nil {
			break
		}
		p.outBuffer = append(p.outBuffer, msgs...)
	}
}

func (p *FromtReshareProtocol) Result() (*PhaseResult, error) {
	if p.cachedResult != nil || p.cachedErr != nil {
		return p.cachedResult, p.cachedErr
	}
	p.cachedResult, p.cachedErr = p.computeResult()
	return p.cachedResult, p.cachedErr
}

func (p *FromtReshareProtocol) computeResult() (*PhaseResult, error) {
	if !p.finished {
		return nil, fmt.Errorf("fromt reshare not finished")
	}

	newKeyShare, _, err := fromt.ReshareSessionResult(p.session)
	if err != nil {
		return nil, fmt.Errorf("fromt reshare result: %w", err)
	}

	pk, err := fromt.KeySharePublicKey(newKeyShare)
	if err != nil {
		return nil, fmt.Errorf("fromt public key: %w", err)
	}

	return &PhaseResult{
		PublicKey: fmt.Sprintf("%x", pk),
		Keyshare:  base64.StdEncoding.EncodeToString(newKeyShare),
	}, nil
}

func (p *FromtReshareProtocol) Free() error {
	return fromt.ReshareSessionFree(p.session)
}
