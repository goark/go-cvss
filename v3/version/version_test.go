package version

import "testing"

func TestVersion(t *testing.T) {
	v := "3.0"
	if Version != v {
		t.Errorf("Version = %v, want %v.", Version, v)
	}
}
