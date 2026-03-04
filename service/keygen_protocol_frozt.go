package service

import (
	"encoding/base64"
	"fmt"
	"sort"

	frozt "github.com/vultisig/frost-zm/go/frozt"
)

const (
	froztStepInit            = 0
	froztStepWaitR1          = 1
	froztStepWaitR2          = 2
	froztStepWaitMetadata    = 3
	froztStepWaitMetaHash    = 4
	froztStepFinished        = 5
)

type FroztKeygenProtocol struct {
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

	secret1    frozt.DkgSecretHandle
	secret2    frozt.DkgSecretHandle
	r1Map      []byte
	r2Map      []byte
	r1Package  []byte

	keyPackage    []byte
	pubKeyPackage []byte
	metadataBytes []byte
	metadataHash  []byte

	peerMessages map[string][]byte
	outBuffer    []OutboundMsg
}

func NewFroztKeygenProtocol(
	name, messagePrefix string,
	localPartyID string,
	parties []string,
) (*FroztKeygenProtocol, error) {
	myId := getFrostIdStatic(localPartyID, parties)
	if myId == 0 {
		return nil, fmt.Errorf("frozt: local party %s not found", localPartyID)
	}
	n := uint16(len(parties))
	return &FroztKeygenProtocol{
		name:       name,
		msgPrefix:  messagePrefix,
		myId:       myId,
		maxSigners: n,
		minSigners: n,
		peerCount:  len(parties) - 1,
		parties:    parties,
		localParty: localPartyID,
		peerMessages: make(map[string][]byte),
	}, nil
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

func getPartyForFrostIdStatic(frostId uint16, parties []string) string {
	sorted := make([]string, len(parties))
	copy(sorted, parties)
	sort.Strings(sorted)
	idx := int(frostId) - 1
	if idx < 0 || idx >= len(sorted) {
		return ""
	}
	return sorted[idx]
}

func (p *FroztKeygenProtocol) Name() string     { return p.name }
func (p *FroztKeygenProtocol) IsFinished() bool  { return p.finished }

func (p *FroztKeygenProtocol) MessageID() string {
	switch p.step {
	case froztStepInit, froztStepWaitR1:
		return p.msgPrefix + "-r1"
	case froztStepWaitR2:
		return p.msgPrefix + "-r2"
	case froztStepWaitMetadata:
		return p.msgPrefix + "-metadata"
	case froztStepWaitMetaHash:
		return p.msgPrefix + "-metadata-hash"
	default:
		return p.msgPrefix
	}
}

func (p *FroztKeygenProtocol) DrainOutbound(parties []string) ([]OutboundMsg, error) {
	if p.step == froztStepInit {
		secret1, r1Package, err := frozt.DkgPart1(p.myId, p.maxSigners, p.minSigners)
		if err != nil {
			return nil, fmt.Errorf("frozt DkgPart1: %w", err)
		}
		p.secret1 = secret1
		p.r1Package = r1Package
		p.step = froztStepWaitR1
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

func (p *FroztKeygenProtocol) ProcessInbound(from string, body []byte) (bool, error) {
	if from == p.localParty {
		return false, nil
	}
	if getFrostIdStatic(from, p.parties) == 0 {
		return false, fmt.Errorf("frozt: unexpected sender %s", from)
	}

	switch p.step {
	case froztStepWaitR1:
		return p.processR1(from, body)
	case froztStepWaitR2:
		return p.processR2(from, body)
	case froztStepWaitMetadata:
		return p.processMetadata(from, body)
	case froztStepWaitMetaHash:
		return p.processMetaHash(from, body)
	default:
		return false, nil
	}
}

func (p *FroztKeygenProtocol) processR1(from string, body []byte) (bool, error) {
	p.peerMessages[from] = body
	if len(p.peerMessages) < p.peerCount {
		return false, nil
	}

	p.r1Map = buildFrostMapStatic(p.peerMessages, p.parties)

	secret2, r2PackagesEncoded, err := frozt.DkgPart2(p.secret1, p.r1Map)
	if err != nil {
		return false, fmt.Errorf("frozt DkgPart2: %w", err)
	}
	p.secret2 = secret2

	r2Packages, err := frozt.DecodeMap(r2PackagesEncoded)
	if err != nil {
		return false, fmt.Errorf("frozt DecodeMap r2: %w", err)
	}

	p.outBuffer = nil
	for _, entry := range r2Packages {
		target := getPartyForFrostIdStatic(entry.ID, p.parties)
		if target == "" || target == p.localParty {
			continue
		}
		p.outBuffer = append(p.outBuffer, OutboundMsg{To: target, Body: entry.Value})
	}

	p.step = froztStepWaitR2
	p.peerMessages = make(map[string][]byte)
	return false, nil
}

func (p *FroztKeygenProtocol) processR2(from string, body []byte) (bool, error) {
	p.peerMessages[from] = body
	if len(p.peerMessages) < p.peerCount {
		return false, nil
	}

	p.r2Map = buildFrostMapStatic(p.peerMessages, p.parties)

	keyPackage, pubKeyPackage, err := frozt.DkgPart3(p.secret2, p.r1Map, p.r2Map)
	if err != nil {
		return false, fmt.Errorf("frozt DkgPart3: %w", err)
	}
	p.keyPackage = keyPackage
	p.pubKeyPackage = pubKeyPackage

	p.step = froztStepWaitMetadata
	p.peerMessages = make(map[string][]byte)
	return false, nil
}

func (p *FroztKeygenProtocol) processMetadata(from string, body []byte) (bool, error) {
	p.metadataBytes = body

	metadataHash, err := frozt.KeygenMetadataHash(p.metadataBytes)
	if err != nil {
		return false, fmt.Errorf("frozt hash metadata: %w", err)
	}
	p.metadataHash = metadataHash

	p.outBuffer = nil
	for _, peer := range p.parties {
		if peer == p.localParty {
			continue
		}
		p.outBuffer = append(p.outBuffer, OutboundMsg{To: peer, Body: metadataHash})
	}

	p.step = froztStepWaitMetaHash
	p.peerMessages = make(map[string][]byte)
	return false, nil
}

func (p *FroztKeygenProtocol) processMetaHash(from string, body []byte) (bool, error) {
	p.peerMessages[from] = body
	if len(p.peerMessages) < p.peerCount {
		return false, nil
	}

	myHashHex := fmt.Sprintf("%x", p.metadataHash)
	for partyID, peerHash := range p.peerMessages {
		peerHashHex := fmt.Sprintf("%x", peerHash)
		if peerHashHex != myHashHex {
			return false, fmt.Errorf("frozt metadata hash mismatch with %s", partyID)
		}
	}

	p.step = froztStepFinished
	p.finished = true
	return true, nil
}

func (p *FroztKeygenProtocol) Result() (*PhaseResult, error) {
	if !p.finished {
		return nil, fmt.Errorf("frozt not finished")
	}

	extras, birthday, err := frozt.KeygenMetadataParse(p.metadataBytes)
	if err != nil {
		return nil, fmt.Errorf("frozt parse metadata: %w", err)
	}

	bundle, err := frozt.KeyShareBundlePack(p.keyPackage, p.pubKeyPackage, extras, birthday)
	if err != nil {
		return nil, fmt.Errorf("frozt bundle pack: %w", err)
	}

	vk, err := frozt.PubKeyPackageVerifyingKey(p.pubKeyPackage)
	if err != nil {
		return nil, fmt.Errorf("frozt verifying key: %w", err)
	}

	return &PhaseResult{
		PublicKey: fmt.Sprintf("%x", vk),
		Keyshare:  base64.StdEncoding.EncodeToString(bundle),
	}, nil
}

func (p *FroztKeygenProtocol) Free() error {
	var firstErr error
	if p.secret2 != 0 {
		firstErr = p.secret2.Close()
		p.secret2 = 0
	}
	if p.secret1 != 0 {
		err := p.secret1.Close()
		if firstErr == nil {
			firstErr = err
		}
		p.secret1 = 0
	}
	return firstErr
}

func buildFrostMapStatic(partyDataMap map[string][]byte, parties []string) []byte {
	entries := make([]frozt.MapEntry, 0, len(partyDataMap))
	for partyID, data := range partyDataMap {
		frostId := getFrostIdStatic(partyID, parties)
		if frostId == 0 {
			continue
		}
		entries = append(entries, frozt.MapEntry{ID: frostId, Value: data})
	}
	return frozt.EncodeMap(entries)
}
