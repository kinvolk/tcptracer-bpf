// +build linux

package tracer

import (
	"fmt"

	bpflib "github.com/iovisor/gobpf/elf"
	"github.com/weaveworks/tcptracer-bpf/pkg/offsetguess"
)

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

func InitializeIPv4(module *bpflib.Module, eventChan chan []byte) (*bpflib.PerfMap, error) {
	return initialize(module, "tcp_event_ipv4", eventChan)
}

func InitializeIPv6(module *bpflib.Module, eventChan chan []byte) (*bpflib.PerfMap, error) {
	return initialize(module, "tcp_event_ipv6", eventChan)
}
