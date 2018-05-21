package version

import (
	"fmt"
	"runtime"
)

var gitCommit = "built incorrectly"

// String returns a formatted strings representing the program's build
// version. It's intended to be used with "--verison" flags.
func String() string {
	return fmt.Sprintf(
		`Version: %s
Go version: %s
OS/Arch: %s/%s
Cgo enabled: %v`,
		gitCommit,
		runtime.Version(),
		runtime.GOOS,
		runtime.GOARCH,
		cgoEnabled,
	)
}
