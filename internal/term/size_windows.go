//go:build windows

package term

import "os"

// Size returns a sensible default on Windows.
func Size() (rows, cols int) { return 30, 100 }

// OnResize is a no-op on Windows.
func OnResize() <-chan os.Signal { return make(chan os.Signal, 1) }
