//go:build !windows

package term

// EnableVirtualTerminal is a no-op on Unix terminals where ANSI sequences are
// already interpreted by the terminal emulator.
func EnableVirtualTerminal(fd uintptr) (func(), error) {
	return func() {}, nil
}
