// +build !linux

package tracer

import (
	"fmt"

	bpflib "github.com/iovisor/gobpf/elf"
)

func InitializeIPv4(module *bpflib.Module, eventChan chan []byte) (*bpflib.PerfMap, error) {
	return nil, fmt.Errorf("not supported on non-Linux systems")
}

func InitializeIPv6(module *bpflib.Module, eventChan chan []byte) (*bpflib.PerfMap, error) {
	return nil, fmt.Errorf("not supported on non-Linux systems")
}
