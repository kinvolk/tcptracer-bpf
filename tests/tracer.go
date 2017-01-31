package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"

	"github.com/weaveworks/tcptracer-bpf/pkg/event"
	"github.com/weaveworks/tcptracer-bpf/pkg/tracer"
)

var lastTimestampV4 uint64
var lastTimestampV6 uint64

func tcpEventCbV4(e event.TcpV4) {
	timestamp := uint64(e.Timestamp)
	cpu := e.CPU
	typ := event.EventType(e.Type)
	pid := e.Pid & 0xffffffff
	comm := string(e.Comm[:bytes.IndexByte(e.Comm[:], 0)])

	saddrbuf := make([]byte, 4)
	daddrbuf := make([]byte, 4)

	binary.LittleEndian.PutUint32(saddrbuf, uint32(e.SAddr))
	binary.LittleEndian.PutUint32(daddrbuf, uint32(e.DAddr))

	sIP := net.IPv4(saddrbuf[0], saddrbuf[1], saddrbuf[2], saddrbuf[3])
	dIP := net.IPv4(daddrbuf[0], daddrbuf[1], daddrbuf[2], daddrbuf[3])

	sport := e.SPort
	dport := e.DPort
	netns := e.NetNS

	fmt.Printf("%v cpu#%d %s %v %s %v:%v %v:%v %v\n", timestamp, cpu, typ, pid, comm, sIP, sport, dIP, dport, netns)

	if lastTimestampV4 > timestamp {
		fmt.Printf("ERROR: late event!\n")
		os.Exit(1)
	}

	lastTimestampV4 = timestamp
}

func tcpEventCbV6(e event.TcpV6) {
	timestamp := uint64(e.Timestamp)
	cpu := e.CPU
	typ := event.EventType(e.Type)
	pid := e.Pid & 0xffffffff
	comm := string(e.Comm[:bytes.IndexByte(e.Comm[:], 0)])

	saddrbuf := make([]byte, 16)
	daddrbuf := make([]byte, 16)

	binary.LittleEndian.PutUint64(saddrbuf, e.SAddrH)
	binary.LittleEndian.PutUint64(saddrbuf[8:], e.SAddrL)
	binary.LittleEndian.PutUint64(daddrbuf, e.DAddrH)
	binary.LittleEndian.PutUint64(daddrbuf[8:], e.DAddrL)

	sIP := net.IP(saddrbuf)
	dIP := net.IP(daddrbuf)

	sport := e.SPort
	dport := e.DPort
	netns := e.NetNS

	fmt.Printf("%v cpu#%d %s %v %s %v:%v %v:%v %v\n", timestamp, cpu, typ, pid, comm, sIP, sport, dIP, dport, netns)

	if lastTimestampV6 > timestamp {
		fmt.Printf("ERROR: late event!\n")
		os.Exit(1)
	}

	lastTimestampV6 = timestamp
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s .../tcptracer-ebpf.o\n", os.Args[0])
		os.Exit(1)
	}
	fileName := os.Args[1]

	t, err := tracer.NewTracerFromFile(fileName, tcpEventCbV4, tcpEventCbV6)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	<-sig
	t.Stop()
}
