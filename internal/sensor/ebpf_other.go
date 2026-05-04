//go:build !linux

package sensor

import "fmt"

// newEBPFManager is not available on non-Linux platforms.
// This function should never be called because manager.go guards with runtime.GOOS.
func newEBPFManager(_ Config) (Manager, error) {
	return nil, fmt.Errorf("eBPF is only supported on Linux")
}
