//go:build darwin

package term

import (
	"syscall"
	"unsafe"
)

// State stores a terminal mode snapshot so it can be restored.
type State struct {
	termios syscall.Termios
}

// MakeRaw switches fd into raw-ish mode: no canonical input, no terminal
// echo, one byte at a time. It returns the previous state.
func MakeRaw(fd uintptr) (*State, error) {
	var old syscall.Termios
	if err := ioctlTermios(fd, syscall.TIOCGETA, &old); err != nil {
		return nil, err
	}

	raw := old
	raw.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	raw.Oflag &^= syscall.OPOST
	raw.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.IEXTEN | syscall.ISIG
	raw.Cflag &^= syscall.CSIZE | syscall.PARENB
	raw.Cflag |= syscall.CS8
	raw.Cc[syscall.VMIN] = 1
	raw.Cc[syscall.VTIME] = 0

	if err := ioctlTermios(fd, syscall.TIOCSETA, &raw); err != nil {
		return nil, err
	}
	return &State{termios: old}, nil
}

// Restore returns fd to a previously saved terminal state.
func Restore(fd uintptr, state *State) error {
	if state == nil {
		return nil
	}
	return ioctlTermios(fd, syscall.TIOCSETA, &state.termios)
}

func ioctlTermios(fd uintptr, req uintptr, termios *syscall.Termios) error {
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		fd,
		req,
		uintptr(unsafe.Pointer(termios)),
	)
	if errno != 0 {
		return errno
	}
	return nil
}
