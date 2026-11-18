package packet

import (
	"encoding/binary"
	"fmt"
)

// SNIRange returns the byte range of the server_name value inside a full TLS
// ClientHello record (header included). ok is false when the record has no SNI.
func SNIRange(record []byte) (start, end int, ok bool) {
	return sniValueRange(record)
}

// SNIMidpoint returns an offset inside the record that cuts the SNI value in
// half, or a fallback offset when no SNI is present.
func SNIMidpoint(record []byte) int {
	if s, e, ok := sniValueRange(record); ok && e > s {
		return s + (e-s)/2
	}
	if len(record) > 6 {
		return len(record) / 2
	}
	return 0
}

// SplitTLSRecord re-frames a single TLS record into two records split at
// payload offset `at` (absolute offset in the original record, header
// included). TLS allows a handshake message to span records, so a conforming
// server reassembles it, while naive DPI parsing a single record does not see
// the full SNI. Returns the original record when the split point is invalid.
func SplitTLSRecord(record []byte, at int) []byte {
	if len(record) < 7 {
		return record
	}
	n := int(binary.BigEndian.Uint16(record[3:5]))
	if 5+n != len(record) {
		return record
	}
	cut := at - 5 // payload offset
	if cut <= 0 || cut >= n {
		return record
	}
	out := make([]byte, 0, len(record)+5)
	out = append(out, record[0], record[1], record[2])
	out = binary.BigEndian.AppendUint16(out, uint16(cut))
	out = append(out, record[5:5+cut]...)
	out = append(out, record[0], record[1], record[2])
	out = binary.BigEndian.AppendUint16(out, uint16(n-cut))
	out = append(out, record[5+cut:]...)
	return out
}

// SplitTLSRecordsAtSNI splits the record so the SNI value is cut across two
// TLS records; when no SNI is found it splits in the middle of the payload.
func SplitTLSRecordsAtSNI(record []byte) []byte {
	return SplitTLSRecord(record, SNIMidpoint(record))
}

// FitFakeToLength returns a fake ClientHello record of exactly n bytes for
// in-stream (TTL limited) fakes: it is truncated or zero-padded, and the fake
// SNI must survive truncation. sni is the fake hostname, used to rebuild with
// the compact legacy template when the preferred fake is too long.
func FitFakeToLength(fake []byte, n int, sni string) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("packet: fake target length %d", n)
	}
	if len(fake) <= n {
		out := make([]byte, n)
		copy(out, fake)
		return out, nil
	}
	if _, e, ok := sniValueRange(fake); ok && e <= n {
		return append([]byte(nil), fake[:n]...), nil
	}
	legacy, err := BuildLegacyClientHelloRecord(sni)
	if err != nil {
		return nil, err
	}
	if len(legacy) <= n {
		out := make([]byte, n)
		copy(out, legacy)
		return out, nil
	}
	if _, e, ok := sniValueRange(legacy); ok && e <= n {
		return append([]byte(nil), legacy[:n]...), nil
	}
	return nil, fmt.Errorf("packet: real ClientHello (%d bytes) too short to carry the fake SNI", n)
}
