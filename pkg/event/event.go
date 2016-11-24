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

// TcpV4 should be in sync with the struct in the ebpf maps.
type TcpV4 struct {
	Timestamp uint64
	CPU       uint64
	Type      EventType
	Pid       uint32
	Comm      [16]byte
	SAddr     uint32
	DAddr     uint32
	SPort     uint16
	DPort     uint16
	NetNS     uint32
}

// TcpV6 should be in sync with the struct in the ebpf maps.
type TcpV6 struct {
	Timestamp uint64
	CPU       uint64
	Type      EventType
	Pid       uint32
	Comm      [16]byte
	SAddrH    uint64
	SAddrL    uint64
	DAddrH    uint64
	DAddrL    uint64
	SPort     uint16
	DPort     uint16
	NetNS     uint32
}
