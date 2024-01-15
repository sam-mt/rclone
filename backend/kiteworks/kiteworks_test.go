// Test Kiteworks filesystem interface
package kiteworks_test

import (
	"testing"

	"github.com/rclone/rclone/backend/kiteworks"
	"github.com/rclone/rclone/fstest/fstests"
)

// TestIntegration runs integration tests against the remote
func TestIntegration(t *testing.T) {
	fstests.Run(t, &fstests.Opt{
		RemoteName: "TestKiteworks:",
		NilObject:  (*kiteworks.Object)(nil),
	})
}
