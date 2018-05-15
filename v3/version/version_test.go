package version

import "testing"

func TestVersion(t *testing.T) {
	if Version != "3.0" {
		t.Errorf("Version = %v, want %v.", Version, "3.0")
	}
}
