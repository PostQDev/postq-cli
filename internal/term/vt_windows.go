//go:build windows

package term

// EnableVirtualTerminal turns on ANSI escape-sequence handling for a Windows
// console output handle. It returns a restore function that resets the
// previous console mode. If stdout is redirected, it returns a no-op restore.
func EnableVirtualTerminal(fd uintptr) (func(), error) {
	mode, err := getConsoleMode(fd)
	if err != nil {
		return func() {}, err
	}
	newMode := mode | enableProcessedOutput | enableVirtualTerminalOutput
	if err := setConsoleMode(fd, newMode); err != nil {
		return func() {}, err
	}
	return func() { _ = setConsoleMode(fd, mode) }, nil
}
