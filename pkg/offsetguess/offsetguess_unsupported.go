// +build !linux

package offsetguess

import (
	"fmt"

	"github.com/iovisor/gobpf/elf"
)

func Guess(b *elf.Module) error {
	return fmt.Errorf("not supported on non-Linux systems")
}
