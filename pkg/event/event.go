package event

import (
	"encoding/binary"
	"net"
	"unsafe"
)

/*
#include "../../tcptracer-bpf.h"
*/
import "C"

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

func TcpV4ToGo(data *[]byte) (ret TcpV4) {
	eventC := (*C.struct_tcp_ipv4_event_t)(unsafe.Pointer(&(*data)[0]))

	ret.Timestamp = uint64(eventC.timestamp)
	ret.CPU = uint64(eventC.cpu)
	ret.Type = EventType(eventC._type)
	ret.Pid = uint32(eventC.pid & 0xffffffff)
	ret.Comm = C.GoString(&eventC.comm[0])

	saddrbuf := make([]byte, 4)
	daddrbuf := make([]byte, 4)

	binary.LittleEndian.PutUint32(saddrbuf, uint32(eventC.saddr))
	binary.LittleEndian.PutUint32(daddrbuf, uint32(eventC.daddr))

	ret.SAddr = net.IPv4(saddrbuf[0], saddrbuf[1], saddrbuf[2], saddrbuf[3])
	ret.DAddr = net.IPv4(daddrbuf[0], daddrbuf[1], daddrbuf[2], daddrbuf[3])

	ret.SPort = uint16(eventC.sport)
	ret.DPort = uint16(eventC.dport)
	ret.NetNS = uint32(eventC.netns)

	return
}

func TcpV6ToGo(data *[]byte) (ret TcpV6) {
	eventC := (*C.struct_tcp_ipv6_event_t)(unsafe.Pointer(&(*data)[0]))

	ret.Timestamp = uint64(eventC.timestamp)
	ret.CPU = uint64(eventC.cpu)
	ret.Type = EventType(eventC._type)
	ret.Pid = uint32(eventC.pid & 0xffffffff)
	ret.Comm = C.GoString(&eventC.comm[0])

	saddrbuf := make([]byte, 16)
	daddrbuf := make([]byte, 16)

	binary.LittleEndian.PutUint64(saddrbuf, uint64(eventC.saddr_h))
	binary.LittleEndian.PutUint64(saddrbuf[8:], uint64(eventC.saddr_l))
	binary.LittleEndian.PutUint64(daddrbuf, uint64(eventC.daddr_h))
	binary.LittleEndian.PutUint64(daddrbuf[8:], uint64(eventC.daddr_l))

	ret.SAddr = net.IP(saddrbuf)
	ret.DAddr = net.IP(daddrbuf)

	ret.SPort = uint16(eventC.sport)
	ret.DPort = uint16(eventC.dport)
	ret.NetNS = uint32(eventC.netns)

	return
}
