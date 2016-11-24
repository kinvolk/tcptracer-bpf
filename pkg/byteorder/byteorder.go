package byteorder

import (
	"encoding/binary"
	"unsafe"
)

var Host binary.ByteOrder

// In lack of binary.HostEndian ...
func init() {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		Host = binary.LittleEndian
	} else {
		Host = binary.BigEndian
	}
}
