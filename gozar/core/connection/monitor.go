package connection

import (
	"net"
	"sync"
)

type ConnID struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

type MonitorConnection struct {
	Monitor   bool
	SynSeq    int64
	SynAckSeq int64
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	ID        ConnID
	Mu        sync.Mutex
	Sock      net.Conn
}

func NewMonitorConnection(sock net.Conn, srcIP, dstIP string, srcPort, dstPort uint16) *MonitorConnection {
	return &MonitorConnection{
		Monitor:   true,
		SynSeq:    -1,
		SynAckSeq: -1,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		ID: ConnID{
			SrcIP:   srcIP,
			SrcPort: srcPort,
			DstIP:   dstIP,
			DstPort: dstPort,
		},
		Sock: sock,
	}
}
