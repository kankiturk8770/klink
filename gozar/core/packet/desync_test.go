package packet

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestSplitTLSRecordRoundTrip(t *testing.T) {
	rec, err := BuildLegacyClientHelloRecord("example.com")
	if err != nil {
		t.Fatal(err)
	}
	s, e, ok := SNIRange(rec)
	if !ok || string(rec[s:e]) != "example.com" {
		t.Fatalf("SNI range wrong: %v %q", ok, rec[s:e])
	}
	split := SplitTLSRecordsAtSNI(rec)
	if len(split) != len(rec)+5 {
		t.Fatalf("len = %d, want %d", len(split), len(rec)+5)
	}
	// Reassemble payloads.
	var payload []byte
	for off := 0; off < len(split); {
		if split[off] != 22 {
			t.Fatalf("record type %d at %d", split[off], off)
		}
		n := int(binary.BigEndian.Uint16(split[off+3 : off+5]))
		payload = append(payload, split[off+5:off+5+n]...)
		off += 5 + n
	}
	if !bytes.Equal(payload, rec[5:]) {
		t.Fatal("payload mismatch after split")
	}
	if bytes.Contains(split[:5+(len(split)-10)/2], []byte("example.com")) && bytes.Contains(split, []byte("example.com")) {
		t.Fatal("SNI must not be contiguous after split")
	}
}

func TestSplitTLSRecordInvalidPoint(t *testing.T) {
	rec, _ := BuildLegacyClientHelloRecord("a.com")
	if got := SplitTLSRecord(rec, 3); !bytes.Equal(got, rec) {
		t.Fatal("split inside header must be a no-op")
	}
	if got := SplitTLSRecord(rec, len(rec)); !bytes.Equal(got, rec) {
		t.Fatal("split at end must be a no-op")
	}
}

func TestFitFakeToLength(t *testing.T) {
	fake, _ := BuildLegacyClientHelloRecord("fake.example")
	pad, err := FitFakeToLength(fake, len(fake)+100, "fake.example")
	if err != nil || len(pad) != len(fake)+100 || !bytes.Equal(pad[:len(fake)], fake) {
		t.Fatalf("pad: %v", err)
	}
	cut, err := FitFakeToLength(fake, 300, "fake.example")
	if err != nil || len(cut) != 300 || !bytes.Contains(cut, []byte("fake.example")) {
		t.Fatalf("truncate: %v", err)
	}
	if _, err := FitFakeToLength(fake, 20, "fake.example"); err == nil {
		t.Fatal("expected error when too short for SNI")
	}
}
