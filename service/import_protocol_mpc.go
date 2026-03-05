package service

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

type MPCImportProtocol struct {
	name         string
	msgID        string
	isEdDSA      bool
	handle       Handle
	wrapper      *MPCWrapperImp
	finished     bool
	outBuffer    []OutboundMsg
	cachedResult *PhaseResult
	cachedErr    error
}

func NewMPCImportProtocol(
	name, messageID string,
	setupMsg []byte,
	localPartyID string,
	isEdDSA bool,
) (*MPCImportProtocol, error) {
	wrapper := NewMPCWrapperImp(isEdDSA, false)

	handle, err := wrapper.KeyImporterNew(setupMsg, localPartyID)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s import session: %w", name, err)
	}
	return &MPCImportProtocol{
		name:    name,
		msgID:   messageID,
		isEdDSA: isEdDSA,
		handle:  handle,
		wrapper: wrapper,
	}, nil
}

func (p *MPCImportProtocol) Name() string      { return p.name }
func (p *MPCImportProtocol) MessageID() string  { return p.msgID }
func (p *MPCImportProtocol) IsFinished() bool   { return p.finished }

func (p *MPCImportProtocol) DrainOutbound(parties []string) ([]OutboundMsg, error) {
	buffered := p.outBuffer
	p.outBuffer = nil

	for {
		outbound, err := p.wrapper.KeygenSessionOutputMessage(p.handle)
		if err != nil {
			return buffered, fmt.Errorf("%s output message: %w", p.name, err)
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

func (p *MPCImportProtocol) resolveReceivers(outbound []byte, parties []string) ([]OutboundMsg, error) {
	var msgs []OutboundMsg
	for i := range parties {
		receiver, err := p.wrapper.KeygenSessionMessageReceiver(p.handle, outbound, i)
		if err != nil {
			return nil, fmt.Errorf("%s message receiver: %w", p.name, err)
		}
		if receiver == "" {
			continue
		}
		msgs = append(msgs, OutboundMsg{To: receiver, Body: outbound})
	}
	return msgs, nil
}

func (p *MPCImportProtocol) ProcessInbound(from string, body []byte) (bool, error) {
	isFinished, err := p.wrapper.KeygenSessionInputMessage(p.handle, body)
	if err != nil {
		return false, fmt.Errorf("%s input message from %s: %w", p.name, from, err)
	}
	if isFinished {
		p.finished = true
		return true, nil
	}
	return false, nil
}

func (p *MPCImportProtocol) Result() (*PhaseResult, error) {
	if p.cachedResult != nil || p.cachedErr != nil {
		return p.cachedResult, p.cachedErr
	}
	p.cachedResult, p.cachedErr = p.computeResult()
	return p.cachedResult, p.cachedErr
}

func (p *MPCImportProtocol) computeResult() (*PhaseResult, error) {
	if !p.finished {
		return nil, fmt.Errorf("%s not finished", p.name)
	}
	keyshareHandle, err := p.wrapper.KeygenSessionFinish(p.handle)
	if err != nil {
		return nil, fmt.Errorf("%s finish: %w", p.name, err)
	}
	defer func() {
		_ = p.wrapper.KeyshareFree(keyshareHandle)
	}()

	buf, err := p.wrapper.KeyshareToBytes(keyshareHandle)
	if err != nil {
		return nil, fmt.Errorf("%s keyshare to bytes: %w", p.name, err)
	}

	pubKeyBytes, err := p.wrapper.KeysharePublicKey(keyshareHandle)
	if err != nil {
		return nil, fmt.Errorf("%s public key: %w", p.name, err)
	}

	chainCode := ""
	if !p.isEdDSA {
		chainCodeBytes, ccErr := p.wrapper.KeyshareChainCode(keyshareHandle)
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

func (p *MPCImportProtocol) Free() error {
	return p.wrapper.KeygenSessionFree(p.handle)
}
