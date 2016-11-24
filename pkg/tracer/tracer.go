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
