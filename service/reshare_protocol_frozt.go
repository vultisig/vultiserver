package service

import (
	"encoding/base64"
	"fmt"

	frozt "github.com/vultisig/frost-zm/go/frozt"
)

type FroztReshareProtocol struct {
	name         string
	msgID        string
	session      frozt.SessionHandle
	finished     bool
	outBuffer    []OutboundMsg
	oldBundle    []byte
	cachedResult *PhaseResult
	cachedErr    error
}

func NewFroztReshareProtocol(
	name, messageID string,
	setupMsg []byte,
	localPartyID string,
	oldBundle []byte,
) (*FroztReshareProtocol, error) {
	oldKeyPackage, err := frozt.KeyShareBundleKeyPackage(oldBundle)
	if err != nil {
		return nil, fmt.Errorf("frozt unpack old key package: %w", err)
	}

	session, err := frozt.ReshareSessionFromSetup(setupMsg, []byte(localPartyID), oldKeyPackage)
	if err != nil {
		return nil, fmt.Errorf("frozt reshare session: %w", err)
	}

	return &FroztReshareProtocol{
		name:      name,
		msgID:     messageID,
		session:   session,
		oldBundle: oldBundle,
	}, nil
}

func (p *FroztReshareProtocol) Name() string     { return p.name }
func (p *FroztReshareProtocol) MessageID() string { return p.msgID }
func (p *FroztReshareProtocol) IsFinished() bool  { return p.finished }

func (p *FroztReshareProtocol) DrainOutbound(parties []string) ([]OutboundMsg, error) {
	buffered := p.outBuffer
	p.outBuffer = nil

	for {
		msg, err := frozt.ReshareSessionTakeMsg(p.session)
		if err != nil {
			return buffered, fmt.Errorf("frozt reshare take msg: %w", err)
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

func (p *FroztReshareProtocol) resolveReceivers(msg []byte, parties []string) ([]OutboundMsg, error) {
	var msgs []OutboundMsg
	for i := range parties {
		receiver, err := frozt.ReshareSessionMsgReceiver(p.session, msg, i)
		if err != nil {
			return nil, fmt.Errorf("frozt reshare msg receiver: %w", err)
		}
		if len(receiver) == 0 {
			continue
		}
		msgs = append(msgs, OutboundMsg{To: string(receiver), Body: msg})
	}
	return msgs, nil
}

func (p *FroztReshareProtocol) ProcessInbound(from string, body []byte) (bool, error) {
	finished, err := frozt.ReshareSessionFeed(p.session, body)
	if err != nil {
		return false, fmt.Errorf("frozt reshare feed from %s: %w", from, err)
	}
	if finished {
		p.finished = true
		return true, nil
	}
	return false, nil
}

func (p *FroztReshareProtocol) Result() (*PhaseResult, error) {
	if p.cachedResult != nil || p.cachedErr != nil {
		return p.cachedResult, p.cachedErr
	}
	p.cachedResult, p.cachedErr = p.computeResult()
	return p.cachedResult, p.cachedErr
}

func (p *FroztReshareProtocol) computeResult() (*PhaseResult, error) {
	if !p.finished {
		return nil, fmt.Errorf("frozt reshare not finished")
	}

	newKeyPackage, newPubKeyPackage, err := frozt.ReshareSessionResult(p.session)
	if err != nil {
		return nil, fmt.Errorf("frozt reshare result: %w", err)
	}

	saplingExtras, err := frozt.KeyShareBundleSaplingExtras(p.oldBundle)
	if err != nil {
		return nil, fmt.Errorf("frozt unpack sapling extras: %w", err)
	}

	birthday, err := frozt.KeyShareBundleBirthday(p.oldBundle)
	if err != nil {
		return nil, fmt.Errorf("frozt unpack birthday: %w", err)
	}

	newBundle, err := frozt.KeyShareBundlePack(newKeyPackage, newPubKeyPackage, saplingExtras, birthday)
	if err != nil {
		return nil, fmt.Errorf("frozt repack bundle: %w", err)
	}

	vk, err := frozt.PubKeyPackageVerifyingKey(newPubKeyPackage)
	if err != nil {
		return nil, fmt.Errorf("frozt verifying key: %w", err)
	}

	return &PhaseResult{
		PublicKey: fmt.Sprintf("%x", vk),
		Keyshare:  base64.StdEncoding.EncodeToString(newBundle),
	}, nil
}

func (p *FroztReshareProtocol) Free() error {
	return frozt.ReshareSessionFree(p.session)
}
