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

package event

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

// Tcp should be in sync with the struct in the ebpf maps.
type Tcp struct {
	// Timestamp must be the first field, the sorting depends on it
	Timestamp uint64

	CPU   uint64
	Type  EventType
	Pid   uint32
	Comm  [16]byte
	SAddr uint32
	DAddr uint32
	SPort uint16
	DPort uint16
	NetNS uint32
}
