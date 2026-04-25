//go:build windows

package term

import (
	"syscall"
	"unsafe"
)

const (
	enableProcessedInput        = 0x0001
	enableLineInput             = 0x0002
	enableEchoInput             = 0x0004
	enableQuickEditMode         = 0x0040
	enableExtendedFlags         = 0x0080
	enableVirtualTerminalInput  = 0x0200
	enableProcessedOutput       = 0x0001
	enableVirtualTerminalOutput = 0x0004
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

// State stores a Windows console mode snapshot so it can be restored.
type State struct {
	mode uint32
}

// MakeRaw switches fd into a raw-ish Windows console input mode. It disables
// line editing/echo so PostQ owns prompt rendering, and enables virtual
// terminal input so arrow/page keys arrive as ANSI escape sequences.
func MakeRaw(fd uintptr) (*State, error) {
	mode, err := getConsoleMode(fd)
	if err != nil {
		return nil, err
	}

	raw := mode
	raw &^= enableLineInput | enableEchoInput
	// Leave ENABLE_PROCESSED_INPUT on so Ctrl+C continues to raise the normal
	// console control event in addition to our signal handling.
	raw |= enableProcessedInput | enableExtendedFlags | enableVirtualTerminalInput
	raw &^= enableQuickEditMode

	if err := setConsoleMode(fd, raw); err != nil {
		return nil, err
	}
	return &State{mode: mode}, nil
}

// Restore returns fd to a previously saved console input mode.
func Restore(fd uintptr, state *State) error {
	if state == nil {
		return nil
	}
	return setConsoleMode(fd, state.mode)
}

func getConsoleMode(fd uintptr) (uint32, error) {
	var mode uint32
	r1, _, errno := procGetConsoleMode.Call(fd, uintptr(unsafe.Pointer(&mode)))
	if r1 == 0 {
		return 0, errno
	}
	return mode, nil
}

func setConsoleMode(fd uintptr, mode uint32) error {
	r1, _, errno := procSetConsoleMode.Call(fd, uintptr(mode))
	if r1 == 0 {
		return errno
	}
	return nil
}
