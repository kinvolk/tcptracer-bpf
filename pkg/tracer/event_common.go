package tracer

import (
	"net"
)

type EventType uint32

// These constants should be in sync with the equivalent definitions in the ebpf program.
const (
	_ EventType = iota
	EventConnect
	EventAccept
	EventClose
)

func (e EventType) String() string {
	switch e {
	case EventConnect:
		return "connect"
	case EventAccept:
		return "accept"
	case EventClose:
		return "close"
	default:
		return "unknown"
	}
}

type TcpV4 struct {
	Timestamp uint64
	CPU       uint64
	Type      EventType
	Pid       uint32
	Comm      string
	SAddr     net.IP
	DAddr     net.IP
	SPort     uint16
	DPort     uint16
	NetNS     uint32
}

type TcpV6 struct {
	Timestamp uint64
	CPU       uint64
	Type      EventType
	Pid       uint32
	Comm      string
	SAddr     net.IP
	DAddr     net.IP
	SPort     uint16
	DPort     uint16
	NetNS     uint32
}
