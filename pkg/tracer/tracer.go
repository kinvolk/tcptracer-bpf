// +build linux

package tracer

import (
	"fmt"

	bpflib "github.com/iovisor/gobpf/elf"
	"github.com/weaveworks/tcptracer-bpf/pkg/event"
	"github.com/weaveworks/tcptracer-bpf/pkg/offsetguess"
)

type Tracer struct {
	m           *bpflib.Module
	perfMapIPV4 *bpflib.PerfMap
	perfMapIPV6 *bpflib.PerfMap
}

func NewTracerFromFile(fileName string, tcpEventCbV4 func(event.TcpV4), tcpEventCbV6 func(event.TcpV6)) (*Tracer, error) {
	m := bpflib.NewModule(fileName)
	if m == nil {
		return nil, fmt.Errorf("BPF not supported")
	}

	err := m.Load()
	if err != nil {
		return nil, err
	}

	err = m.EnableKprobes()
	if err != nil {
		return nil, err
	}

	channelV4 := make(chan []byte)
	channelV6 := make(chan []byte)

	perfMapIPV4, err := initializeIPv4(m, channelV4)
	if err != nil {
		return nil, fmt.Errorf("failed to init perf map for IPv4 events: %s\n", err)
	}

	perfMapIPV6, err := initializeIPv6(m, channelV6)
	if err != nil {
		return nil, fmt.Errorf("failed to init perf map for IPv6 events: %s\n", err)
	}

	go func() {
		for {
			data := <-channelV4
			tcpEventCbV4(event.TcpV4ToGo(&data))
		}
	}()

	go func() {
		for {
			data := <-channelV6
			tcpEventCbV6(event.TcpV6ToGo(&data))
		}
	}()

	perfMapIPV4.PollStart()
	perfMapIPV6.PollStart()

	return &Tracer{
		m:           m,
		perfMapIPV4: perfMapIPV4,
		perfMapIPV6: perfMapIPV6,
	}, nil
}

func (t *Tracer) Stop() {
	t.perfMapIPV4.PollStop()
	t.perfMapIPV6.PollStop()
}

func initialize(module *bpflib.Module, eventMapName string, eventChan chan []byte) (*bpflib.PerfMap, error) {
	if err := offsetguess.Guess(module); err != nil {
		return nil, fmt.Errorf("error guessing offsets: %v", err)
	}

	pm, err := bpflib.InitPerfMap(module, eventMapName, eventChan)
	if err != nil {
		return nil, fmt.Errorf("error initializing perf map for %q: %v", eventMapName, err)
	}

	return pm, nil

}

func initializeIPv4(module *bpflib.Module, eventChan chan []byte) (*bpflib.PerfMap, error) {
	return initialize(module, "tcp_event_ipv4", eventChan)
}

func initializeIPv6(module *bpflib.Module, eventChan chan []byte) (*bpflib.PerfMap, error) {
	return initialize(module, "tcp_event_ipv6", eventChan)
}
