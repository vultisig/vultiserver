package service

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	mldsaSession "github.com/vultisig/go-wrappers/mldsa"
)

type MPCKeygenProtocol struct {
	name      string
	msgID     string
	isEdDSA   bool
	isMldsa   bool
	handle    Handle
	wrapper   *MPCWrapperImp
	finished  bool
	failed    bool
	lastErr   error
	outBuffer []OutboundMsg
}

func NewMPCKeygenProtocol(
	name, messageID string,
	setupMsg []byte,
	localPartyID string,
	isEdDSA, isMldsa bool,
) (*MPCKeygenProtocol, error) {
	wrapper := NewMPCWrapperImp(isEdDSA, isMldsa)
	handle, err := wrapper.KeygenSessionFromSetup(mldsaSession.MlDsa44, setupMsg, []byte(localPartyID))
	if err != nil {
		return nil, fmt.Errorf("failed to create %s session: %w", name, err)
	}
	return &MPCKeygenProtocol{
		name:    name,
		msgID:   messageID,
		isEdDSA: isEdDSA,
		isMldsa: isMldsa,
		handle:  handle,
		wrapper: wrapper,
	}, nil
}

func (p *MPCKeygenProtocol) Name() string      { return p.name }
func (p *MPCKeygenProtocol) MessageID() string  { return p.msgID }
func (p *MPCKeygenProtocol) IsFinished() bool   { return p.finished }

func (p *MPCKeygenProtocol) DrainOutbound(parties []string) ([]OutboundMsg, error) {
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

func (p *MPCKeygenProtocol) resolveReceivers(outbound []byte, parties []string) ([]OutboundMsg, error) {
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

func (p *MPCKeygenProtocol) ProcessInbound(from string, body []byte) (bool, error) {
	isFinished, err := p.wrapper.KeygenSessionInputMessage(p.handle, body)
	if err != nil {
		p.lastErr = err
		return false, fmt.Errorf("%s input message from %s: %w", p.name, from, err)
	}
	if isFinished {
		p.finished = true
		return true, nil
	}
	return false, nil
}

func (p *MPCKeygenProtocol) Result() (*PhaseResult, error) {
	if !p.finished {
		return nil, fmt.Errorf("%s not finished", p.name)
	}
	keyshareHandle, err := p.wrapper.KeygenSessionFinish(p.handle)
	if err != nil {
		return nil, fmt.Errorf("%s finish: %w", p.name, err)
	}

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
		chainCodeBytes, err := p.wrapper.KeyshareChainCode(keyshareHandle)
		if err != nil {
			return nil, fmt.Errorf("%s chain code: %w", p.name, err)
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

func (p *MPCKeygenProtocol) Free() error {
	return p.wrapper.KeygenSessionFree(p.handle)
}
