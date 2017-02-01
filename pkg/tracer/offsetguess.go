// +build linux

package tracer

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/iovisor/gobpf/elf"
)

/*
#include "../../tcptracer-bpf.h"
*/
import "C"

type tcpTracerStatus C.struct_tcptracer_status_t

const (
	threshold         = 200
	thresholdInetSock = 2000
)

const (
	uninitialized C.__u64 = iota
	checking
	checked
	ready
)

const (
	guessSaddr C.__u64 = iota
	guessDaddr
	guessFamily
	guessSport
	guessDport
	guessNetns
	guessDaddrIPv6
)

const listenIP = "127.0.0.2"

var zero uint64

type freePort struct {
	port uint16
	err  error
}

type fieldValues struct {
	saddr     uint32
	daddr     uint32
	sport     uint16
	dport     uint16
	netns     uint32
	family    uint16
	daddrIPv6 [4]uint32
}

func listenV4(listenCompleted chan freePort, closeListen chan struct{}) {
	// port 0 means we let the kernel choose a free port
	url := fmt.Sprintf("%s:0", listenIP)
	l, err := net.Listen("tcp4", url)
	if err != nil {
		listenCompleted <- freePort{port: 0, err: err}
		return
	}

	lport, err := strconv.Atoi(strings.Split(l.Addr().String(), ":")[1])
	if err != nil {
		listenCompleted <- freePort{port: 0, err: err}
		return
	}

	listenCompleted <- freePort{port: uint16(lport), err: nil}
	close(listenCompleted)

	select {
	case <-closeListen:
		l.Close()
		return
	}
}

func compareIPv6(a [4]C.__u32, b [4]uint32) bool {
	for i := 0; i < 4; i++ {
		if a[i] != C.__u32(b[i]) {
			return false
		}
	}
	return true
}

func ownNetNS() (uint64, error) {
	var s syscall.Stat_t
	if err := syscall.Stat("/proc/self/ns/net", &s); err != nil {
		return 0, err
	}
	return s.Ino, nil
}

func ipv6FromUint32Arr(ipv6Addr [4]uint32) net.IP {
	buf := make([]byte, 16)
	for i := 0; i < 16; i++ {
		buf[i] = *(*byte)(unsafe.Pointer((uintptr(unsafe.Pointer(&ipv6Addr[0])) + uintptr(i))))
	}
	return net.IP(buf)
}

func htons(a uint16) uint16 {
	var arr [2]byte
	binary.BigEndian.PutUint16(arr[:], a)
	return nativeEndian.Uint16(arr[:])
}

// tryCurrentOffset creates a IPv4 or IPv6 connection so the corresponding
// tcp_v{4,6}_connect kprobes get triggered and save the value at the current
// offset in the eBPF map
func tryCurrentOffset(module *elf.Module, mp *elf.Map, status *tcpTracerStatus, expected *fieldValues) error {
	// for ipv6, we don't need the source port because we already guessed
	// it doing ipv4 connections so we use a random destination address and
	// try to connect to it
	expected.daddrIPv6[0] = rand.Uint32()
	expected.daddrIPv6[1] = rand.Uint32()
	expected.daddrIPv6[2] = rand.Uint32()
	expected.daddrIPv6[3] = rand.Uint32()

	ip := ipv6FromUint32Arr(expected.daddrIPv6)

	bindAddress := fmt.Sprintf("%s:%d", listenIP, expected.dport)
	if status.what != guessDaddrIPv6 {
		conn, err := net.Dial("tcp4", bindAddress)
		if err != nil {
			return fmt.Errorf("error dialing %q: %v\n", bindAddress, err)
		}

		// get the source port assigned by the kernel
		sport, err := strconv.Atoi(strings.Split(conn.LocalAddr().String(), ":")[1])
		if err != nil {
			return fmt.Errorf("error converting source port: %v", err)
		}

		expected.sport = uint16(sport)

		// set SO_LINGER to 0 so the connection state after closing is
		// CLOSE instead of TIME_WAIT. In this way, they will disappear
		// from the conntrack table after around 10 seconds instead of 2
		// minutes
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetLinger(0)
		} else {
			return fmt.Errorf("not a tcp connection unexpectedly")
		}

		conn.Close()
	} else {
		conn, err := net.Dial("tcp6", fmt.Sprintf("[%s]:9092", ip))
		// Since we connect to a random IP, this will most likely fail.
		// In the unlikely case where it connects successfully, we close
		// the connection to avoid a leak.
		if err == nil {
			conn.Close()
		}
	}

	return nil
}

// checkAndUpdateCurrentOffset checks the value for the current offset stored
// in the eBPF map against the expected value, incrementing the offset if it
// doesn't match, or going to the next field to guess if it does
func checkAndUpdateCurrentOffset(module *elf.Module, mp *elf.Map, status *tcpTracerStatus, expected *fieldValues) error {
	// get the updated map value so we can check if the current offset is
	// the right one
	if err := module.LookupElement(mp, unsafe.Pointer(&zero), unsafe.Pointer(status)); err != nil {
		return fmt.Errorf("error reading tcptracer_status: %v", err)
	}

	if status.status != checked {
		return fmt.Errorf("invalid guessing state")
	}

	switch status.what {
	case guessSaddr:
		if status.saddr == C.__u32(expected.saddr) {
			status.what = guessDaddr
			status.status = checking
		} else {
			status.offset_saddr++
			status.status = checking
			status.saddr = C.__u32(expected.saddr)
		}
	case guessDaddr:
		if status.daddr == C.__u32(expected.daddr) {
			status.what = guessFamily
			status.status = checking
		} else {
			status.offset_daddr++
			status.status = checking
			status.daddr = C.__u32(expected.daddr)
		}
	case guessFamily:
		if status.family == C.__u16(expected.family) {
			status.what = guessSport
			status.status = checking
			// we know the sport ((struct inet_sock)->inet_sport) is
			// after the family field, so we start from there
			status.offset_sport = status.offset_family
		} else {
			status.offset_family++
			status.status = checking
		}
	case guessSport:
		if status.sport == C.__u16(htons(expected.sport)) {
			status.what = guessDport
			status.status = checking
		} else {
			status.offset_sport++
			status.status = checking
		}
	case guessDport:
		if status.dport == C.__u16(htons(expected.dport)) {
			status.what = guessNetns
			status.status = checking
		} else {
			status.offset_dport++
			status.status = checking
		}
	case guessNetns:
		if status.netns == C.__u32(expected.netns) {
			status.what = guessDaddrIPv6
			status.status = checking
		} else {
			status.offset_ino++
			// go to the next offset_netns if we get an error
			if status.err != 0 || status.offset_ino >= threshold {
				status.offset_ino = 0
				status.offset_netns++
			}
			status.status = checking
		}
	case guessDaddrIPv6:
		if compareIPv6(status.daddr_ipv6, expected.daddrIPv6) {
			// at this point, we've guessed all the offsets we need,
			// set the status to "ready"
			status.status = ready
		} else {
			status.offset_daddr_ipv6++
			status.status = checking
		}
	default:
		return fmt.Errorf("unexpected field to guess")
	}

	// update the map with the new offset/field to check
	if err := module.UpdateElement(mp, unsafe.Pointer(&zero), unsafe.Pointer(status), 0); err != nil {
		return fmt.Errorf("error updating tcptracer_status: %v", err)
	}

	return nil
}

// guess expects elf.Module to hold a tcptracer-bpf object and initializes the
// tracer by guessing the right struct sock kernel struct offsets. Results are
// stored in the `tcptracer_status` map as used by the module.
//
// To guess the offsets, we create connections from localhost (127.0.0.1) to
// 127.0.0.2:$PORT, where we have a server listening. We store the current
// possible offset and expected value of each field in a eBPF map. Each
// connection will trigger the eBPF program attached to tcp_v{4,6}_connect
// where, for each field to guess, we store the value of
//     (struct sock *)skp + possible_offset
// in the eBPF map. Then, back in userspace (checkAndUpdateCurrentOffset()), we
// check that value against the expected value of the field, advancing the
// offset and repeating the process until we find the value we expect. Then, we
// guess the next field.
func guess(b *elf.Module) error {
	currentNetns, err := ownNetNS()
	if err != nil {
		return fmt.Errorf("error getting current netns: %v", err)
	}

	mp := b.Map("tcptracer_status")

	pidTgid := uint64(os.Getpid()<<32 | syscall.Gettid())

	status := &tcpTracerStatus{
		status:   checking,
		pid_tgid: C.__u64(pidTgid),
	}

	// if we already have the offsets, just return
	err = b.LookupElement(mp, unsafe.Pointer(&zero), unsafe.Pointer(status))
	if err == nil && status.status == ready {
		return nil
	}

	listenCompleted := make(chan freePort)
	closeListen := make(chan struct{})

	var listenPort uint16
	go listenV4(listenCompleted, closeListen)
	select {
	case p := <-listenCompleted:
		if p.err != nil {
			return err
		}
		listenPort = p.port
	}
	defer close(closeListen)

	// initialize map
	if err := b.UpdateElement(mp, unsafe.Pointer(&zero), unsafe.Pointer(status), 0); err != nil {
		return fmt.Errorf("error initializing tcptracer_status map: %v", err)
	}

	expected := &fieldValues{
		// 127.0.0.1
		saddr: 0x0100007F,
		// 127.0.0.2
		daddr: 0x0200007F,
		// will be set later
		sport:  0,
		dport:  listenPort,
		netns:  uint32(currentNetns),
		family: syscall.AF_INET,
	}

	for status.status != ready {
		if err := tryCurrentOffset(b, mp, status, expected); err != nil {
			return err
		}

		if err := checkAndUpdateCurrentOffset(b, mp, status, expected); err != nil {
			return err
		}

		// stop at a reasonable offset so we don't run forever
		if status.offset_saddr >= threshold || status.offset_daddr >= threshold ||
			status.offset_sport >= thresholdInetSock || status.offset_dport >= threshold ||
			status.offset_netns >= threshold || status.offset_family >= threshold ||
			status.offset_daddr_ipv6 >= 200 {
			return fmt.Errorf("overflow, bailing out")
		}
	}

	return nil
}
