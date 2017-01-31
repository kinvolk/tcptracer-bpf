// +build !linux

package tracer

import (
	"fmt"

	"github.com/weaveworks/tcptracer-bpf/pkg/event"
)

type Tracer struct{}

func NewTracerFromFile(fileName string, tcpEventCbV4 func(event.TcpV4), tcpEventCbV6 func(event.TcpV6)) (*Tracer, error) {
	return nil, fmt.Errorf("not supported on non-Linux systems")
}

func (t *Tracer) Stop() {
}
