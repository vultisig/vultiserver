package service

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

type MPCReshareProtocol struct {
	name           string
	msgID          string
	isEdDSA        bool
	session        Handle
	keyshareHandle Handle
	wrapper        *MPCWrapperImp
	finished       bool
	outBuffer      []OutboundMsg
	cachedResult   *PhaseResult
	cachedErr      error
}

func NewMPCReshareProtocol(
	name, messageID string,
	setupMsg []byte,
	localPartyID string,
	keyshareBytes []byte,
	isEdDSA bool,
) (*MPCReshareProtocol, error) {
	wrapper := NewMPCWrapperImp(isEdDSA, false)

	keyshareHandle, err := wrapper.KeyshareFromBytes(keyshareBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to load %s keyshare: %w", name, err)
	}

	session, err := wrapper.QcSessionFromSetup(setupMsg, localPartyID, keyshareHandle)
	if err != nil {
		_ = wrapper.KeyshareFree(keyshareHandle)
		return nil, fmt.Errorf("failed to create %s QC session: %w", name, err)
	}

	return &MPCReshareProtocol{
		name:           name,
		msgID:          messageID,
		isEdDSA:        isEdDSA,
		session:        session,
		keyshareHandle: keyshareHandle,
		wrapper:        wrapper,
	}, nil
}

func (p *MPCReshareProtocol) Name() string      { return p.name }
func (p *MPCReshareProtocol) MessageID() string  { return p.msgID }
func (p *MPCReshareProtocol) IsFinished() bool   { return p.finished }

func (p *MPCReshareProtocol) DrainOutbound(parties []string) ([]OutboundMsg, error) {
	buffered := p.outBuffer
	p.outBuffer = nil

	for {
		outbound, err := p.wrapper.QcSessionOutputMessage(p.session)
		if err != nil {
			return buffered, fmt.Errorf("%s QC output message: %w", p.name, err)
		}
		if len(outbound) == 0 {
			break
		}
		msgs, err := p.resolveReceivers(outbound, parties)
		if err != nil {
			return buffered, err
		}
		buffered = append(buffered, msgs...)
	}
	return buffered, nil
}

func (p *MPCReshareProtocol) resolveReceivers(outbound []byte, parties []string) ([]OutboundMsg, error) {
	var msgs []OutboundMsg
	for i := range parties {
		receiver, err := p.wrapper.QcSessionMessageReceiver(p.session, outbound, i)
		if err != nil {
			return nil, fmt.Errorf("%s QC message receiver: %w", p.name, err)
		}
		if receiver == "" {
			continue
		}
		msgs = append(msgs, OutboundMsg{To: receiver, Body: outbound})
	}
	return msgs, nil
}

func (p *MPCReshareProtocol) ProcessInbound(from string, body []byte) (bool, error) {
	isFinished, err := p.wrapper.QcSessionInputMessage(p.session, body)
	if err != nil {
		return false, fmt.Errorf("%s QC input from %s: %w", p.name, from, err)
	}
	if isFinished {
		p.finished = true
		return true, nil
	}
	return false, nil
}

func (p *MPCReshareProtocol) Result() (*PhaseResult, error) {
	if p.cachedResult != nil || p.cachedErr != nil {
		return p.cachedResult, p.cachedErr
	}
	p.cachedResult, p.cachedErr = p.computeResult()
	return p.cachedResult, p.cachedErr
}

func (p *MPCReshareProtocol) computeResult() (*PhaseResult, error) {
	if !p.finished {
		return nil, fmt.Errorf("%s not finished", p.name)
	}

	newKeyshareHandle, err := p.wrapper.QcSessionFinish(p.session)
	if err != nil {
		return nil, fmt.Errorf("%s QC finish: %w", p.name, err)
	}
	defer func() {
		_ = p.wrapper.KeyshareFree(newKeyshareHandle)
	}()

	buf, err := p.wrapper.KeyshareToBytes(newKeyshareHandle)
	if err != nil {
		return nil, fmt.Errorf("%s keyshare to bytes: %w", p.name, err)
	}

	pubKeyBytes, err := p.wrapper.KeysharePublicKey(newKeyshareHandle)
	if err != nil {
		return nil, fmt.Errorf("%s public key: %w", p.name, err)
	}

	chainCode := ""
	if !p.isEdDSA {
		chainCodeBytes, ccErr := p.wrapper.KeyshareChainCode(newKeyshareHandle)
		if ccErr != nil {
			return nil, fmt.Errorf("%s chain code: %w", p.name, ccErr)
		}
		if chainCodeBytes != nil {
			chainCode = hex.EncodeToString(chainCodeBytes)
		}
	}

	return &PhaseResult{
		PublicKey: hex.EncodeToString(pubKeyBytes),
		ChainCode: chainCode,
		Keyshare:  base64.StdEncoding.EncodeToString(buf),
	}, nil
}

func (p *MPCReshareProtocol) Free() error {
	_ = p.wrapper.KeyshareFree(p.keyshareHandle)
	return nil
}
