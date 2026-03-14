package service

import (
	"encoding/binary"
	"testing"
)

func TestDecodeFroztSetupPartyIDs(t *testing.T) {
	setup := encodeFroztSignSetupForTest(
		[]froztPartyForTest{
			{id: 1, name: "windows-3073"},
			{id: 2, name: "Server-5230"},
		},
		[]byte{0xaa, 0xbb},
	)

	partyIDs, ordered, err := decodeFroztSetupPartyIDs(setup)
	if err != nil {
		t.Fatalf("decodeFroztSetupPartyIDs returned error: %v", err)
	}

	if len(ordered) != 2 || ordered[0] != "windows-3073" || ordered[1] != "Server-5230" {
		t.Fatalf("unexpected ordered parties: %#v", ordered)
	}

	if partyIDs["windows-3073"] != 1 {
		t.Fatalf("unexpected windows frost id: %d", partyIDs["windows-3073"])
	}

	if partyIDs["Server-5230"] != 2 {
		t.Fatalf("unexpected server frost id: %d", partyIDs["Server-5230"])
	}
}

func TestDecodeFroztSetupPartyIDsRejectsTruncatedSetup(t *testing.T) {
	setup := encodeFroztSignSetupForTest(
		[]froztPartyForTest{
			{id: 1, name: "windows-3073"},
			{id: 2, name: "Server-5230"},
		},
		[]byte{0xaa},
	)

	_, _, err := decodeFroztSetupPartyIDs(setup[:18])
	if err == nil {
		t.Fatal("expected decodeFroztSetupPartyIDs to fail on truncated setup")
	}
}

type froztPartyForTest struct {
	id   uint16
	name string
}

func encodeFroztSignSetupForTest(parties []froztPartyForTest, message []byte) []byte {
	buf := make([]byte, 0, 64)

	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(parties)))
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(parties)))
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(parties)))

	for _, party := range parties {
		buf = binary.LittleEndian.AppendUint16(buf, party.id)
		buf = binary.LittleEndian.AppendUint16(buf, uint16(len(party.name)))
		buf = append(buf, party.name...)
	}

	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(message)))
	buf = append(buf, message...)

	return buf
}
