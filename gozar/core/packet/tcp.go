// Package packet implements raw IPv4/TCP accessors for nfqueue / WinDivert captures.
package packet

import (
	"encoding/binary"
	"fmt"
	"net"
)

type TCPFlags struct {
	SYN bool
	ACK bool
	RST bool
	FIN bool
	PSH bool
	URG bool
}

func IPVersion(raw []byte) int {
	if len(raw) == 0 {
		return 0
	}
	return int(raw[0] >> 4)
}

func IPHeaderLen(raw []byte) int {
	if len(raw) == 0 {
		return 0
	}
	return int(raw[0]&0x0F) * 4
}

func tcpOffset(raw []byte) int {
	return IPHeaderLen(raw)
}

func IPv4SrcAddr(raw []byte) net.IP {
	if len(raw) < 16 {
		return nil
	}
	return net.IP(raw[12:16])
}

func IPv4DstAddr(raw []byte) net.IP {
	if len(raw) < 20 {
		return nil
	}
	return net.IP(raw[16:20])
}

func IPv4TotalLen(raw []byte) uint16 {
	if len(raw) < 4 {
		return 0
	}
	return binary.BigEndian.Uint16(raw[2:4])
}

func SetIPv4TotalLen(raw []byte, length uint16) {
	if len(raw) < 4 {
		return
	}
	binary.BigEndian.PutUint16(raw[2:4], length)
}

func IPv4Ident(raw []byte) uint16 {
	if len(raw) < 6 {
		return 0
	}
	return binary.BigEndian.Uint16(raw[4:6])
}

func SetIPv4Ident(raw []byte, ident uint16) {
	if len(raw) < 6 {
		return
	}
	binary.BigEndian.PutUint16(raw[4:6], ident)
}

// ClearIPv4DontFragment clears the IPv4 DF bit (allows fragmentation when oversized).
func ClearIPv4DontFragment(raw []byte) {
	if len(raw) < 7 || IPVersion(raw) != 4 {
		return
	}
	raw[6] &^= 0x40
}

func TCPSrcPort(raw []byte) uint16 {
	off := tcpOffset(raw)
	if len(raw) < off+4 {
		return 0
	}
	return binary.BigEndian.Uint16(raw[off : off+2])
}

func TCPDstPort(raw []byte) uint16 {
	off := tcpOffset(raw)
	if len(raw) < off+4 {
		return 0
	}
	return binary.BigEndian.Uint16(raw[off+2 : off+4])
}

func TCPSeqNum(raw []byte) uint32 {
	off := tcpOffset(raw)
	if len(raw) < off+8 {
		return 0
	}
	return binary.BigEndian.Uint32(raw[off+4 : off+8])
}

func SetTCPSeqNum(raw []byte, seq uint32) {
	off := tcpOffset(raw)
	if len(raw) < off+8 {
		return
	}
	binary.BigEndian.PutUint32(raw[off+4:off+8], seq)
}

func TCPAckNum(raw []byte) uint32 {
	off := tcpOffset(raw)
	if len(raw) < off+12 {
		return 0
	}
	return binary.BigEndian.Uint32(raw[off+8 : off+12])
}

func SetTCPAckNum(raw []byte, ack uint32) {
	off := tcpOffset(raw)
	if len(raw) < off+12 {
		return
	}
	binary.BigEndian.PutUint32(raw[off+8:off+12], ack)
}

func TCPDataOffset(raw []byte) int {
	off := tcpOffset(raw)
	if len(raw) < off+13 {
		return 0
	}
	return int(raw[off+12]>>4) * 4
}

func GetTCPFlags(raw []byte) TCPFlags {
	off := tcpOffset(raw)
	if len(raw) < off+14 {
		return TCPFlags{}
	}
	flags := raw[off+13]
	return TCPFlags{
		FIN: flags&0x01 != 0,
		SYN: flags&0x02 != 0,
		RST: flags&0x04 != 0,
		PSH: flags&0x08 != 0,
		ACK: flags&0x10 != 0,
		URG: flags&0x20 != 0,
	}
}

func SetTCPFlag(raw []byte, flag string, value bool) {
	off := tcpOffset(raw)
	if len(raw) < off+14 {
		return
	}
	var mask byte
	switch flag {
	case "fin":
		mask = 0x01
	case "syn":
		mask = 0x02
	case "rst":
		mask = 0x04
	case "psh":
		mask = 0x08
	case "ack":
		mask = 0x10
	case "urg":
		mask = 0x20
	}
	if value {
		raw[off+13] |= mask
	} else {
		raw[off+13] &^= mask
	}
}

func TCPPayload(raw []byte) []byte {
	ipHdrLen := IPHeaderLen(raw)
	tcpHdrLen := TCPDataOffset(raw)
	payloadStart := ipHdrLen + tcpHdrLen
	if payloadStart >= len(raw) {
		return nil
	}
	return raw[payloadStart:]
}

func TCPPayloadLen(raw []byte) int {
	payload := TCPPayload(raw)
	if payload == nil {
		return 0
	}
	return len(payload)
}

// SetTCPPayload replaces the TCP payload; returns a new slice or nil if headers are invalid.
func SetTCPPayload(raw []byte, payload []byte) []byte {
	if len(raw) < 20 {
		return nil
	}
	ipHdrLen := IPHeaderLen(raw)
	if ipHdrLen < 20 || ipHdrLen > 60 || len(raw) < ipHdrLen {
		return nil
	}
	tcpHdrLen := TCPDataOffset(raw)
	if tcpHdrLen < 20 || tcpHdrLen > 60 {
		return nil
	}
	headerTotal := ipHdrLen + tcpHdrLen
	if headerTotal > len(raw) || headerTotal < ipHdrLen+20 {
		return nil
	}

	newRaw := make([]byte, headerTotal+len(payload))
	copy(newRaw, raw[:headerTotal])
	copy(newRaw[headerTotal:], payload)

	SetIPv4TotalLen(newRaw, uint16(len(newRaw)))

	return newRaw
}

func PacketSummary(raw []byte) string {
	if len(raw) < 40 {
		return fmt.Sprintf("<packet too short: %d bytes>", len(raw))
	}
	flags := GetTCPFlags(raw)
	flagStr := ""
	if flags.SYN {
		flagStr += "SYN "
	}
	if flags.ACK {
		flagStr += "ACK "
	}
	if flags.RST {
		flagStr += "RST "
	}
	if flags.FIN {
		flagStr += "FIN "
	}
	if flags.PSH {
		flagStr += "PSH "
	}
	return fmt.Sprintf("%s:%d → %s:%d [%s] seq=%d ack=%d payload=%d",
		IPv4SrcAddr(raw), TCPSrcPort(raw),
		IPv4DstAddr(raw), TCPDstPort(raw),
		flagStr, TCPSeqNum(raw), TCPAckNum(raw), TCPPayloadLen(raw))
}
