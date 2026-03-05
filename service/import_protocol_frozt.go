package service

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"

	frozt "github.com/vultisig/frost-zm/go/frozt"
)

type FroztImportProtocol struct {
	name         string
	msgID        string
	session      frozt.SessionHandle
	finished     bool
	parties      []string
	outBuffer    []OutboundMsg
	cachedResult *PhaseResult
	cachedErr    error
}

func NewFroztImportProtocol(
	name, messageID string,
	setupMsg []byte,
	localPartyID string,
) (*FroztImportProtocol, error) {
	session, err := frozt.KeyImportSessionFromSetup(setupMsg, []byte(localPartyID))
	if err != nil {
		return nil, fmt.Errorf("frozt import session: %w", err)
	}
	return &FroztImportProtocol{
		name:    name,
		msgID:   messageID,
		session: session,
	}, nil
}

func (p *FroztImportProtocol) Name() string     { return p.name }
func (p *FroztImportProtocol) MessageID() string { return p.msgID }
func (p *FroztImportProtocol) IsFinished() bool  { return p.finished }

func (p *FroztImportProtocol) DrainOutbound(parties []string) ([]OutboundMsg, error) {
	p.parties = parties
	buffered := p.outBuffer
	p.outBuffer = nil

	for {
		msg, err := frozt.KeyImportSessionTakeMsg(p.session)
		if err != nil {
			return buffered, fmt.Errorf("frozt import take msg: %w", err)
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

func (p *FroztImportProtocol) resolveReceivers(msg []byte, parties []string) ([]OutboundMsg, error) {
	payload := msg[2:]
	var msgs []OutboundMsg
	for i := range parties {
		receiver, err := frozt.KeyImportSessionMsgReceiver(p.session, msg, i)
		if err != nil {
			return nil, fmt.Errorf("frozt import msg receiver: %w", err)
		}
		if len(receiver) == 0 {
			continue
		}
		msgs = append(msgs, OutboundMsg{To: string(receiver), Body: payload})
	}
	return msgs, nil
}

func (p *FroztImportProtocol) ProcessInbound(from string, body []byte) (bool, error) {
	senderID := getFrostIdStatic(from, p.parties)
	if senderID == 0 {
		return false, fmt.Errorf("frozt import: unknown sender %s", from)
	}
	frame := make([]byte, 2+len(body))
	binary.LittleEndian.PutUint16(frame, senderID)
	copy(frame[2:], body)

	finished, err := frozt.KeyImportSessionFeed(p.session, frame)
	if err != nil {
		return false, fmt.Errorf("frozt import feed from %s: %w", from, err)
	}
	if finished {
		p.finished = true
		return true, nil
	}
	return false, nil
}

func (p *FroztImportProtocol) Result() (*PhaseResult, error) {
	if p.cachedResult != nil || p.cachedErr != nil {
		return p.cachedResult, p.cachedErr
	}
	p.cachedResult, p.cachedErr = p.computeResult()
	return p.cachedResult, p.cachedErr
}

func (p *FroztImportProtocol) computeResult() (*PhaseResult, error) {
	if !p.finished {
		return nil, fmt.Errorf("frozt import not finished")
	}

	bundle, err := frozt.KeyImportSessionResult(p.session)
	if err != nil {
		return nil, fmt.Errorf("frozt import result: %w", err)
	}

	pubKeyPackage, err := frozt.KeyShareBundlePubKeyPackage(bundle)
	if err != nil {
		return nil, fmt.Errorf("frozt import unpack pubkey package: %w", err)
	}

	vk, err := frozt.PubKeyPackageVerifyingKey(pubKeyPackage)
	if err != nil {
		return nil, fmt.Errorf("frozt import verifying key: %w", err)
	}

	return &PhaseResult{
		PublicKey: fmt.Sprintf("%x", vk),
		Keyshare:  base64.StdEncoding.EncodeToString(bundle),
	}, nil
}

func (p *FroztImportProtocol) Free() error {
	return frozt.KeyImportSessionFree(p.session)
}
