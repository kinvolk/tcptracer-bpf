// Copyright 2017 Kinvolk GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"

	"github.com/iovisor/gobpf/elf"

	"github.com/weaveworks/tcptracer-bpf/pkg/byteorder"
	"github.com/weaveworks/tcptracer-bpf/pkg/offsetguess"
)

type EventType uint32

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

type tcpEventV4 struct {
	// Timestamp must be the first field, the sorting depends on it
	Timestamp uint64

	Cpu   uint64
	Type  uint32
	Pid   uint32
	Comm  [16]byte
	SAddr uint32
	DAddr uint32
	SPort uint16
	DPort uint16
	NetNS uint32
}

type tcpEventV6 struct {
	// Timestamp must be the first field, the sorting depends on it
	Timestamp uint64

	Cpu    uint64
	Type   uint32
	Pid    uint32
	Comm   [16]byte
	SAddrH uint64
	SAddrL uint64
	DAddrH uint64
	DAddrL uint64
	SPort  uint16
	DPort  uint16
	NetNS  uint32
}

var lastTimestampV4 uint64
var lastTimestampV6 uint64

func tcpEventCbV4(event tcpEventV4) {
	timestamp := uint64(event.Timestamp)
	cpu := event.Cpu
	typ := EventType(event.Type)
	pid := event.Pid & 0xffffffff
	comm := string(event.Comm[:bytes.IndexByte(event.Comm[:], 0)])

	saddrbuf := make([]byte, 4)
	daddrbuf := make([]byte, 4)

	binary.LittleEndian.PutUint32(saddrbuf, uint32(event.SAddr))
	binary.LittleEndian.PutUint32(daddrbuf, uint32(event.DAddr))

	sIP := net.IPv4(saddrbuf[0], saddrbuf[1], saddrbuf[2], saddrbuf[3])
	dIP := net.IPv4(daddrbuf[0], daddrbuf[1], daddrbuf[2], daddrbuf[3])

	sport := event.SPort
	dport := event.DPort
	netns := event.NetNS

	fmt.Printf("%v cpu#%d %s %v %s %v:%v %v:%v %v\n", timestamp, cpu, typ, pid, comm, sIP, sport, dIP, dport, netns)

	if lastTimestampV4 > timestamp {
		fmt.Printf("ERROR: late event!\n")
		os.Exit(1)
	}

	lastTimestampV4 = timestamp
}

func tcpEventCbV6(event tcpEventV6) {
	timestamp := uint64(event.Timestamp)
	cpu := event.Cpu
	typ := EventType(event.Type)
	pid := event.Pid & 0xffffffff
	comm := string(event.Comm[:bytes.IndexByte(event.Comm[:], 0)])

	saddrbuf := make([]byte, 16)
	daddrbuf := make([]byte, 16)

	binary.LittleEndian.PutUint64(saddrbuf, event.SAddrH)
	binary.LittleEndian.PutUint64(saddrbuf[8:], event.SAddrL)
	binary.LittleEndian.PutUint64(daddrbuf, event.DAddrH)
	binary.LittleEndian.PutUint64(daddrbuf[8:], event.DAddrL)

	sIP := net.IP(saddrbuf)
	dIP := net.IP(daddrbuf)

	sport := event.SPort
	dport := event.DPort
	netns := event.NetNS

	fmt.Printf("%v cpu#%d %s %v %s %v:%v %v:%v %v\n", timestamp, cpu, typ, pid, comm, sIP, sport, dIP, dport, netns)

	if lastTimestampV6 > timestamp {
		fmt.Printf("ERROR: late event!\n")
		os.Exit(1)
	}

	lastTimestampV6 = timestamp
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s .../ebpf.o\n", os.Args[0])
		os.Exit(1)
	}
	fileName := os.Args[1]

	b := elf.NewModule(fileName)
	if b == nil {
		fmt.Fprintf(os.Stderr, "System doesn't support BPF\n")
		os.Exit(1)
	}

	err := b.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	err = b.EnableKprobes()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	channelV4 := make(chan []byte)
	channelV6 := make(chan []byte)

	perfMapIPV4, err := elf.InitPerfMap(b, "tcp_event_ipv4", channelV4)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	perfMapIPV6, err := elf.InitPerfMap(b, "tcp_event_ipv6", channelV6)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	if err := offsetguess.Guess(b); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		var event tcpEventV4
		for {
			data := <-channelV4
			err := binary.Read(bytes.NewBuffer(data), byteorder.Host, &event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			tcpEventCbV4(event)
		}
	}()

	go func() {
		var event tcpEventV6
		for {
			data := <-channelV6
			err := binary.Read(bytes.NewBuffer(data), byteorder.Host, &event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			tcpEventCbV6(event)
		}
	}()

	perfMapIPV4.PollStart()
	perfMapIPV6.PollStart()
	<-sig
	perfMapIPV4.PollStop()
	perfMapIPV6.PollStop()
}
