package service

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"sort"

	frozt "github.com/vultisig/frost-zm/go/frozt"
)

type FroztKeygenProtocol struct {
	name         string
	msgID        string
	session      frozt.SessionHandle
	finished     bool
	parties      []string
	outBuffer    []OutboundMsg
	cachedResult *PhaseResult
	cachedErr    error
}

func NewFroztKeygenProtocol(
	name, messageID string,
	localPartyID string,
	parties []string,
) (*FroztKeygenProtocol, error) {
	partyInfos := buildFroztPartyInfos(parties)
	n := uint16(len(parties))
	setup, err := frozt.DkgSetupMsgNew(n, n, partyInfos, 0)
	if err != nil {
		return nil, fmt.Errorf("frozt setup: %w", err)
	}

	session, err := frozt.DkgSessionFromSetup(setup, []byte(localPartyID))
	if err != nil {
		return nil, fmt.Errorf("frozt session: %w", err)
	}

	return &FroztKeygenProtocol{
		name:    name,
		msgID:   messageID,
		session: session,
		parties: parties,
	}, nil
}

func (p *FroztKeygenProtocol) Name() string     { return p.name }
func (p *FroztKeygenProtocol) MessageID() string { return p.msgID }
func (p *FroztKeygenProtocol) IsFinished() bool  { return p.finished }

func (p *FroztKeygenProtocol) DrainOutbound(parties []string) ([]OutboundMsg, error) {
	buffered := p.outBuffer
	p.outBuffer = nil

	for {
		msg, err := frozt.DkgSessionTakeMsg(p.session)
		if err != nil {
			return buffered, fmt.Errorf("frozt take msg: %w", err)
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

func (p *FroztKeygenProtocol) resolveReceivers(msg []byte, parties []string) ([]OutboundMsg, error) {
	payload := msg[2:]
	var msgs []OutboundMsg
	for i := range parties {
		receiver, err := frozt.DkgSessionMsgReceiver(p.session, msg, i)
		if err != nil {
			return nil, fmt.Errorf("frozt msg receiver: %w", err)
		}
		if len(receiver) == 0 {
			continue
		}
		msgs = append(msgs, OutboundMsg{To: string(receiver), Body: payload})
	}
	return msgs, nil
}

func (p *FroztKeygenProtocol) ProcessInbound(from string, body []byte) (bool, error) {
	senderID := getFrostIdStatic(from, p.parties)
	if senderID == 0 {
		return false, fmt.Errorf("frozt: unknown sender %s", from)
	}
	frame := make([]byte, 2+len(body))
	binary.LittleEndian.PutUint16(frame, senderID)
	copy(frame[2:], body)

	finished, err := frozt.DkgSessionFeed(p.session, frame)
	if err != nil {
		return false, fmt.Errorf("frozt feed from %s: %w", from, err)
	}
	if finished {
		p.finished = true
		return true, nil
	}
	return false, nil
}

func (p *FroztKeygenProtocol) Result() (*PhaseResult, error) {
	if p.cachedResult != nil || p.cachedErr != nil {
		return p.cachedResult, p.cachedErr
	}
	p.cachedResult, p.cachedErr = p.computeResult()
	return p.cachedResult, p.cachedErr
}

func (p *FroztKeygenProtocol) computeResult() (*PhaseResult, error) {
	if !p.finished {
		return nil, fmt.Errorf("frozt not finished")
	}

	bundle, err := frozt.DkgSessionResult(p.session)
	if err != nil {
		return nil, fmt.Errorf("frozt result: %w", err)
	}

	pubKeyPackage, err := frozt.KeyShareBundlePubKeyPackage(bundle)
	if err != nil {
		return nil, fmt.Errorf("frozt unpack pubkey package: %w", err)
	}

	vk, err := frozt.PubKeyPackageVerifyingKey(pubKeyPackage)
	if err != nil {
		return nil, fmt.Errorf("frozt verifying key: %w", err)
	}

	return &PhaseResult{
		PublicKey: fmt.Sprintf("%x", vk),
		Keyshare:  base64.StdEncoding.EncodeToString(bundle),
	}, nil
}

func (p *FroztKeygenProtocol) Free() error {
	return frozt.DkgSessionFree(p.session)
}

func getFrostIdStatic(localPartyID string, parties []string) uint16 {
	sorted := make([]string, len(parties))
	copy(sorted, parties)
	sort.Strings(sorted)
	for i, p := range sorted {
		if p == localPartyID {
			return uint16(i + 1)
		}
	}
	return 0
}

func buildFroztPartyInfos(parties []string) []frozt.PartyInfo {
	infos := make([]frozt.PartyInfo, len(parties))
	for i, name := range parties {
		infos[i] = frozt.PartyInfo{
			FrostID: getFrostIdStatic(name, parties),
			Name:    []byte(name),
		}
	}
	return infos
}
