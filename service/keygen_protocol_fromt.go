package service

import (
	"encoding/base64"
	"fmt"

	fromt "github.com/vultisig/frost-zm/go/fromt"
)

type FromtKeygenProtocol struct {
	name         string
	msgID        string
	session      *fromt.SessionHandle
	finished     bool
	parties      []string
	outBuffer    []OutboundMsg
	cachedResult *PhaseResult
	cachedErr    error
}

func NewFromtKeygenProtocol(
	name, messageID string,
	localPartyID string,
	parties []string,
) (*FromtKeygenProtocol, error) {
	partyInfos := buildFromtPartyInfos(parties)
	n := uint16(len(parties))
	setup, err := fromt.DkgSetupMsgNew(n, n, partyInfos, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("fromt setup: %w", err)
	}

	session, err := fromt.DkgSessionFromSetup(setup, []byte(localPartyID))
	if err != nil {
		return nil, fmt.Errorf("fromt session: %w", err)
	}

	return &FromtKeygenProtocol{
		name:    name,
		msgID:   messageID,
		session: session,
		parties: parties,
	}, nil
}

func (p *FromtKeygenProtocol) Name() string     { return p.name }
func (p *FromtKeygenProtocol) MessageID() string { return p.msgID }
func (p *FromtKeygenProtocol) IsFinished() bool  { return p.finished }

func (p *FromtKeygenProtocol) DrainOutbound(parties []string) ([]OutboundMsg, error) {
	buffered := p.outBuffer
	p.outBuffer = nil

	for {
		msg, err := fromt.DkgSessionTakeMsg(p.session)
		if err != nil {
			return buffered, fmt.Errorf("fromt take msg: %w", err)
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

func (p *FromtKeygenProtocol) resolveReceivers(msg []byte, parties []string) ([]OutboundMsg, error) {
	var msgs []OutboundMsg
	for i := range parties {
		receiver, err := fromt.DkgSessionMsgReceiver(p.session, msg, i)
		if err != nil {
			return nil, fmt.Errorf("fromt msg receiver: %w", err)
		}
		if len(receiver) == 0 {
			continue
		}
		msgs = append(msgs, OutboundMsg{To: string(receiver), Body: msg})
	}
	return msgs, nil
}

func (p *FromtKeygenProtocol) ProcessInbound(from string, body []byte) (bool, error) {
	finished, err := fromt.DkgSessionFeed(p.session, body)
	if err != nil {
		return false, fmt.Errorf("fromt feed from %s: %w", from, err)
	}
	if finished {
		p.finished = true
		return true, nil
	}
	return false, nil
}

func (p *FromtKeygenProtocol) Result() (*PhaseResult, error) {
	if p.cachedResult != nil || p.cachedErr != nil {
		return p.cachedResult, p.cachedErr
	}
	p.cachedResult, p.cachedErr = p.computeResult()
	return p.cachedResult, p.cachedErr
}

func (p *FromtKeygenProtocol) computeResult() (*PhaseResult, error) {
	if !p.finished {
		return nil, fmt.Errorf("fromt not finished")
	}

	bundle, err := fromt.DkgSessionResult(p.session)
	if err != nil {
		return nil, fmt.Errorf("fromt result: %w", err)
	}

	pk, err := fromt.KeySharePublicKey(bundle)
	if err != nil {
		return nil, fmt.Errorf("fromt public key: %w", err)
	}

	return &PhaseResult{
		PublicKey: fmt.Sprintf("%x", pk),
		Keyshare:  base64.StdEncoding.EncodeToString(bundle),
	}, nil
}

func (p *FromtKeygenProtocol) Free() error {
	return fromt.DkgSessionFree(p.session)
}

func buildFromtPartyInfos(parties []string) []fromt.PartyInfo {
	infos := make([]fromt.PartyInfo, len(parties))
	for i, name := range parties {
		infos[i] = fromt.PartyInfo{
			FrostID: getFrostIdStatic(name, parties),
			Name:    []byte(name),
		}
	}
	return infos
}
