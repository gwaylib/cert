package cert

import "testing"

func TestLoadAutoCert(t *testing.T) {
	if err := AddAutoCert("lib10", "testing"); err != nil {
		t.Fatal(err)
	}
}
