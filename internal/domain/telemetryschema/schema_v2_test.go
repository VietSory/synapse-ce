package telemetryschema

import "testing"

func TestV1AndV2AreConcurrentlySupported(t *testing.T) {
	for _, version := range []int{1, 2} {
		if !Supported(version) {
			t.Fatalf("schema v%d must remain supported by the same build", version)
		}
		if err := Validate(version); err != nil {
			t.Fatalf("Validate(%d): %v", version, err)
		}
	}
	if Current != 2 {
		t.Fatalf("Current = %d, want 2 after defining the v2 contract", Current)
	}
}
