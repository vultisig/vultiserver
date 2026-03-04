package service

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"

	fromt "github.com/vultisig/frost-zm/go/fromt"
)

const (
	fromtStepInit        = 0
	fromtStepWaitR1      = 1
	fromtStepWaitR2      = 2
	fromtStepWaitMeta    = 3
	fromtStepFinished    = 4
)

type FromtKeygenProtocol struct {
	name       string
	msgPrefix  string
	finished   bool
	step       int

	myId       uint16
	maxSigners uint16
	minSigners uint16
	peerCount  int
	parties    []string
	localParty string

	secret1    *fromt.DkgSecretHandle
	secret2    *fromt.DkgSecretHandle
	r1Map      []byte
	r2Map      []byte

	keyShare   []byte
	pubKey     []byte
	network    uint8
	birthday   uint64

	peerMessages map[string][]byte
	outBuffer    []OutboundMsg
}

func NewFromtKeygenProtocol(
	name, messagePrefix string,
	localPartyID string,
	parties []string,
) (*FromtKeygenProtocol, error) {
	myId := getFrostIdStatic(localPartyID, parties)
	if myId == 0 {
		return nil, fmt.Errorf("fromt: local party %s not found", localPartyID)
	}
	n := uint16(len(parties))
	return &FromtKeygenProtocol{
		name:         name,
		msgPrefix:    messagePrefix,
		myId:         myId,
		maxSigners:   n,
		minSigners:   n,
		peerCount:    len(parties) - 1,
		parties:      parties,
		localParty:   localPartyID,
		peerMessages: make(map[string][]byte),
	}, nil
}

func (p *FromtKeygenProtocol) Name() string     { return p.name }
func (p *FromtKeygenProtocol) IsFinished() bool  { return p.finished }

func (p *FromtKeygenProtocol) MessageID() string {
	switch p.step {
	case fromtStepInit, fromtStepWaitR1:
		return p.msgPrefix + "-r1"
	case fromtStepWaitR2:
		return p.msgPrefix + "-r2"
	case fromtStepWaitMeta:
		return p.msgPrefix + "-metadata"
	default:
		return p.msgPrefix
	}
}

func (p *FromtKeygenProtocol) DrainOutbound(parties []string) ([]OutboundMsg, error) {
	if p.step == fromtStepInit {
		secret1, r1Package, err := fromt.DkgPart1(p.myId, p.maxSigners, p.minSigners)
		if err != nil {
			return nil, fmt.Errorf("fromt DkgPart1: %w", err)
		}
		p.secret1 = secret1
		p.step = fromtStepWaitR1
		p.peerMessages = make(map[string][]byte)

		var out []OutboundMsg
		for _, peer := range parties {
			if peer == p.localParty {
				continue
			}
			out = append(out, OutboundMsg{To: peer, Body: r1Package})
		}
		return out, nil
	}

	buffered := p.outBuffer
	p.outBuffer = nil
	return buffered, nil
}

func (p *FromtKeygenProtocol) ProcessInbound(from string, body []byte) (bool, error) {
	if from == p.localParty {
		return false, nil
	}
	if getFrostIdStatic(from, p.parties) == 0 {
		return false, fmt.Errorf("fromt: unexpected sender %s", from)
	}

	switch p.step {
	case fromtStepWaitR1:
		return p.processR1(from, body)
	case fromtStepWaitR2:
		return p.processR2(from, body)
	case fromtStepWaitMeta:
		return p.processMeta(from, body)
	default:
		return false, nil
	}
}

func (p *FromtKeygenProtocol) processR1(from string, body []byte) (bool, error) {
	p.peerMessages[from] = body
	if len(p.peerMessages) < p.peerCount {
		return false, nil
	}

	p.r1Map = buildFromtMap(p.peerMessages, p.parties)

	secret2, r2PackagesEncoded, err := fromt.DkgPart2(p.secret1, p.r1Map)
	if err != nil {
		return false, fmt.Errorf("fromt DkgPart2: %w", err)
	}
	p.secret2 = secret2

	r2Packages, err := fromt.DecodeMap(r2PackagesEncoded)
	if err != nil {
		return false, fmt.Errorf("fromt DecodeMap r2: %w", err)
	}

	p.outBuffer = nil
	for _, entry := range r2Packages {
		targetId, err := fromt.DecodeIdentifier(entry.ID)
		if err != nil {
			continue
		}
		target := getPartyForFrostIdStatic(targetId, p.parties)
		if target == "" || target == p.localParty {
			continue
		}
		p.outBuffer = append(p.outBuffer, OutboundMsg{To: target, Body: entry.Value})
	}

	p.step = fromtStepWaitR2
	p.peerMessages = make(map[string][]byte)
	return false, nil
}

func (p *FromtKeygenProtocol) processR2(from string, body []byte) (bool, error) {
	p.peerMessages[from] = body
	if len(p.peerMessages) < p.peerCount {
		return false, nil
	}

	p.r2Map = buildFromtMap(p.peerMessages, p.parties)

	p.step = fromtStepWaitMeta
	p.peerMessages = make(map[string][]byte)
	return false, nil
}

func (p *FromtKeygenProtocol) processMeta(_ string, body []byte) (bool, error) {
	if len(body) < 9 {
		return false, fmt.Errorf("fromt metadata too short: %d bytes", len(body))
	}
	p.network = body[0]
	p.birthday = binary.LittleEndian.Uint64(body[1:9])

	keyShare, pubKey, err := fromt.DkgPart3(p.secret2, p.r1Map, p.r2Map, p.network, p.birthday)
	if err != nil {
		return false, fmt.Errorf("fromt DkgPart3: %w", err)
	}
	p.keyShare = keyShare
	p.pubKey = pubKey

	p.step = fromtStepFinished
	p.finished = true
	return true, nil
}

func (p *FromtKeygenProtocol) Result() (*PhaseResult, error) {
	if !p.finished {
		return nil, fmt.Errorf("fromt not finished")
	}

	return &PhaseResult{
		PublicKey: fmt.Sprintf("%x", p.pubKey),
		Keyshare:  base64.StdEncoding.EncodeToString(p.keyShare),
	}, nil
}

func (p *FromtKeygenProtocol) Free() error {
	var firstErr error
	if p.secret2 != nil {
		firstErr = p.secret2.Close()
		p.secret2 = nil
	}
	if p.secret1 != nil {
		err := p.secret1.Close()
		if firstErr == nil {
			firstErr = err
		}
		p.secret1 = nil
	}
	return firstErr
}

func buildFromtMap(partyDataMap map[string][]byte, parties []string) []byte {
	entries := make([]fromt.MapEntry, 0, len(partyDataMap))
	for partyID, data := range partyDataMap {
		frostId := getFrostIdStatic(partyID, parties)
		if frostId == 0 {
			continue
		}
		idBytes, err := fromt.EncodeIdentifier(frostId)
		if err != nil {
			continue
		}
		entries = append(entries, fromt.MapEntry{ID: idBytes, Value: data})
	}
	return fromt.EncodeMap(entries)
}
