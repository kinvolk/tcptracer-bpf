// +build linux

package offsetguess

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

	"github.com/weaveworks/tcptracer-bpf/pkg/byteorder"
)

type tcpTracerState uint64

const (
	uninitialized tcpTracerState = iota
	checking
	checked
	ready
)

type guessWhat uint64

const (
	guessSaddr guessWhat = iota
	guessDaddr
	guessFamily
	guessSport
	guessDport
	guessNetns
	guessDaddrIPv6
)

type tcpTracerStatus struct {
	status          tcpTracerState
	pidTgid         uint64
	what            guessWhat
	offsetSaddr     uint64
	offsetDaddr     uint64
	offsetSport     uint64
	offsetDport     uint64
	offsetNetns     uint64
	offsetIno       uint64
	offsetFamily    uint64
	offsetDaddrIPv6 uint64
	err             byte
	saddr           uint32
	daddr           uint32
	sport           uint16
	dport           uint16
	netns           uint32
	family          uint16
	daddrIPv6       [4]uint32
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

func listen(url, netType string, listenCompleted, closeListen chan struct{}) {
	l, err := net.Listen(netType, url)
	if err != nil {
		panic(err)
	}

	close(listenCompleted)

	select {
	case <-closeListen:
		l.Close()
		return
	}
}

func compareIPv6(a, b [4]uint32) bool {
	for i := 0; i < 4; i++ {
		if a[i] != b[i] {
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
	arr := make([]byte, 2)
	binary.BigEndian.PutUint16(arr, a)
	return byteorder.Host.Uint16(arr)
}

func checkAndUpdateCurrentOffset(status *tcpTracerStatus, expected *fieldValues) error {
	if status.status == checked {
		switch status.what {
		case guessSaddr:
			if status.saddr == uint32(expected.saddr) {
				status.what++
				status.status = checking
			} else {
				status.offsetSaddr++
				status.status = checking
				status.saddr = uint32(expected.saddr)
			}
		case guessDaddr:
			if status.daddr == uint32(expected.daddr) {
				status.what++
				status.status = checking
			} else {
				status.offsetDaddr++
				status.status = checking
				status.daddr = uint32(expected.daddr)
			}
		case guessFamily:
			if status.family == uint16(expected.family) {
				status.what++
				status.status = checking
				// we know the sport ((struct inet_sock)->inet_sport) is
				// after the family field, so we start from there
				status.offsetSport = status.offsetFamily
			} else {
				status.offsetFamily++
				status.status = checking
			}
		case guessSport:
			if status.sport == uint16(expected.sport) {
				status.what++
				status.status = checking
			} else {
				status.offsetSport++
				status.status = checking
			}
		case guessDport:
			if status.dport == expected.dport {
				status.what++
				status.status = checking
			} else {
				status.offsetDport++
				status.status = checking
			}
		case guessNetns:
			if status.netns == expected.netns {
				status.what++
				status.status = checking
			} else {
				status.offsetIno++
				// go to the next offsetNetns if we get an error
				if status.err != 0 || status.offsetIno >= 200 {
					status.offsetIno = 0
					status.offsetNetns++
				}
				status.status = checking
			}
		case guessDaddrIPv6:
			if compareIPv6(status.daddrIPv6, expected.daddrIPv6) {
				status.what++
				// at this point, we've guessed all the offsets we need,
				// set the status to "ready"
				status.status = ready
			} else {
				status.offsetDaddrIPv6++
				status.status = checking
			}
		default:
			return fmt.Errorf("unexpected field")
		}
	}

	return nil
}

// Guess expects elf.Module to hold a tcptracer-bpf object and initializes the
// tracer by guessing the right struct sock kernel struct offsets. Results are
// stored in the `tcptracer_status` map as used by the module.
//
// To guess the offsets, we create connections from localhost (127.0.0.1) to
// 127.0.0.2:9091, where we have a server listening. We store the current
// possible offset and expected value of each field in a eBPF map. Each
// connection will trigger the eBPF program attached to tcp_v{4,6}_connect
// where, for each field to guess, we store the value of
//     (struct sock *)skp + possible_offset
// in the eBPF map. Then, back in userspace (checkAndUpdateCurrentOffset()), we
// check that value against the expected value of the field, advancing the
// offset and repeating the process until we find the value we expect. Then, we
// guess the next field.
func Guess(b *elf.Module) error {
	listenIP := "127.0.0.2"
	listenPort := uint16(9091)
	bindAddress := fmt.Sprintf("%s:%d", listenIP, listenPort)

	currentNetns, err := ownNetNS()
	if err != nil {
		return fmt.Errorf("error getting current netns: %v", err)
	}

	mp := b.Map("tcptracer_status")

	var zero uint64
	pidTgid := uint64(os.Getpid()<<32 | syscall.Gettid())

	status := &tcpTracerStatus{
		status:  checking,
		pidTgid: pidTgid,
	}

	// if we already have the offsets, just return
	err = b.LookupElement(mp, unsafe.Pointer(&zero), unsafe.Pointer(status))
	if err == nil && status.status == ready {
		return nil
	}

	listenCompleted := make(chan struct{})
	closeListen := make(chan struct{})

	go listen(bindAddress, "tcp4", listenCompleted, closeListen)
	<-listenCompleted
	defer close(closeListen)

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
		dport:  htons(listenPort),
		netns:  uint32(currentNetns),
		family: syscall.AF_INET,
	}

	for status.status != ready {
		// for ipv6, we don't need the source port because we already guessed
		// it doing ipv4 connections so we use a random destination address and
		// try to connect to it
		expected.daddrIPv6[0] = rand.Uint32()
		expected.daddrIPv6[1] = rand.Uint32()
		expected.daddrIPv6[2] = rand.Uint32()
		expected.daddrIPv6[3] = rand.Uint32()

		ip := ipv6FromUint32Arr(expected.daddrIPv6)

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

			expected.sport = htons(uint16(sport))

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
			if err == nil {
				conn.Close()
			}
		}

		// get the updated map value so we can check if the current offset is
		// the right one
		err = b.LookupElement(mp, unsafe.Pointer(&zero), unsafe.Pointer(status))
		if err != nil {
			return fmt.Errorf("error reading tcptracer_status: %v", err)
		}

		if err := checkAndUpdateCurrentOffset(status, expected); err != nil {
			return err
		}

		// update the map with the new offset/field to check
		if err := b.UpdateElement(mp, unsafe.Pointer(&zero), unsafe.Pointer(status), 0); err != nil {
			return fmt.Errorf("error updating tcptracer_status: %v", err)
		}

		// stop at a reasonable offset so we don't run forever
		if status.offsetSaddr >= 200 || status.offsetDaddr >= 200 ||
			status.offsetSport >= 2000 || status.offsetDport >= 200 ||
			status.offsetNetns >= 200 || status.offsetFamily >= 200 ||
			status.offsetDaddrIPv6 >= 200 {
			return fmt.Errorf("overflow, bailing out")
		}
	}

	return nil
}
