//go:build !darwin && !linux && !windows

package term

// State stores a terminal mode snapshot. On unsupported platforms it is empty.
type State struct{}

// MakeRaw is a no-op fallback on unsupported platforms.
func MakeRaw(fd uintptr) (*State, error) { return &State{}, nil }

// Restore is a no-op fallback on unsupported platforms.
func Restore(fd uintptr, state *State) error { return nil }
