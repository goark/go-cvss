package cvss

import "testing"

func TestVersion(t *testing.T) {
	v := "v3"
	if LatestVersion != v {
		t.Errorf("Version = %v, want %v.", LatestVersion, v)
	}
}
