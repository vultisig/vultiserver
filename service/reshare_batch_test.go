package service

import (
	"reflect"
	"testing"
)

func TestMapOldFrostIDs(t *testing.T) {
	current := []string{"server-2", "server-1", "server-4"}
	old := []string{"server-3", "server-1", "server-2"}

	got := mapOldFrostIDs(old, current)
	want := []uint16{1, 2}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mapOldFrostIDs() = %v, want %v", got, want)
	}
}

func TestBuildFrostPartyInfo(t *testing.T) {
	parties := []string{"server-2", "server-1", "server-3"}

	got := buildFrostPartyInfo(parties)
	if len(got) != 3 {
		t.Fatalf("unexpected party count: %d", len(got))
	}
	if got[0].FrostID != 1 || string(got[0].Name) != "server-1" {
		t.Fatalf("unexpected first party: %+v", got[0])
	}
	if got[2].FrostID != 3 || string(got[2].Name) != "server-3" {
		t.Fatalf("unexpected last party: %+v", got[2])
	}
}
