//go:build windows

package term

import (
	"os"
	"unsafe"
)

type coord struct {
	X int16
	Y int16
}

type smallRect struct {
	Left   int16
	Top    int16
	Right  int16
	Bottom int16
}

type consoleScreenBufferInfo struct {
	Size              coord
	CursorPosition    coord
	Attributes        uint16
	Window            smallRect
	MaximumWindowSize coord
}

var procGetConsoleScreenBufferInfo = kernel32.NewProc("GetConsoleScreenBufferInfo")

// Size returns (rows, cols) of the active Windows console window. Falls
// back to 30x100 if it can't be determined (e.g. redirected output).
func Size() (rows, cols int) {
	var info consoleScreenBufferInfo
	r1, _, _ := procGetConsoleScreenBufferInfo.Call(
		os.Stdout.Fd(),
		uintptr(unsafe.Pointer(&info)),
	)
	if r1 == 0 {
		return 30, 100
	}
	cols = int(info.Window.Right-info.Window.Left) + 1
	rows = int(info.Window.Bottom-info.Window.Top) + 1
	if rows <= 0 || cols <= 0 {
		return 30, 100
	}
	return rows, cols
}

// OnResize is a no-op on Windows.
func OnResize() <-chan os.Signal { return make(chan os.Signal, 1) }
