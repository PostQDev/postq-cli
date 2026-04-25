// Package term provides minimal terminal helpers (size, resize signal)
// using only the Go standard library. Works on darwin & linux; Windows
// falls back to a sensible default size.
package term

import (
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"unsafe"
)

// Size returns (rows, cols) of the controlling terminal. Falls back to
// 24x80 if it can't be determined.
func Size() (rows, cols int) {
	if runtime.GOOS == "windows" {
		return 30, 100
	}
	type winsize struct {
		Row, Col, Xpixel, Ypixel uint16
	}
	var ws winsize
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		os.Stdout.Fd(),
		uintptr(syscall.TIOCGWINSZ),
		uintptr(unsafe.Pointer(&ws)),
	)
	if errno != 0 || ws.Row == 0 || ws.Col == 0 {
		return 24, 80
	}
	return int(ws.Row), int(ws.Col)
}

// OnResize fires the returned channel whenever SIGWINCH arrives. Returns
// a no-op channel on Windows.
func OnResize() <-chan os.Signal {
	ch := make(chan os.Signal, 1)
	if runtime.GOOS == "windows" {
		return ch
	}
	signal.Notify(ch, syscall.SIGWINCH)
	return ch
}
