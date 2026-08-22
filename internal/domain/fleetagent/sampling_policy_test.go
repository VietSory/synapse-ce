package fleetagent

import "testing"

func TestSamplingPolicyDigestCommitsEveryField(t *testing.T) {
	base, err := SamplingPolicyDigest("none", "none", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(base) != 64 {
		t.Fatalf("digest length=%d want=64", len(base))
	}
	cases := []struct {
		name      string
		algorithm string
		policyID  string
		seed      string
		version   uint64
	}{
		{"algorithm", "deterministic", "none", "", 1},
		{"policy-id", "none", "policy-2", "", 1},
		{"seed", "none", "none", "seed", 1},
		{"version", "none", "none", "", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SamplingPolicyDigest(tc.algorithm, tc.policyID, tc.seed, tc.version)
			if err != nil {
				t.Fatal(err)
			}
			if got == base {
				t.Fatalf("changing %s must change digest", tc.name)
			}
		})
	}
	again, err := SamplingPolicyDigest("none", "none", "", 1)
	if err != nil || again != base {
		t.Fatalf("commitment must be deterministic: got=%q want=%q err=%v", again, base, err)
	}
}

func TestSamplingPolicyDigestRejectsIncompleteTuple(t *testing.T) {
	for _, tc := range []struct {
		algorithm string
		policyID  string
		version   uint64
	}{
		{"", "none", 1},
		{"none", "", 1},
		{"none", "none", 0},
	} {
		if _, err := SamplingPolicyDigest(tc.algorithm, tc.policyID, "", tc.version); err == nil {
			t.Fatalf("expected invalid tuple to fail: %+v", tc)
		}
	}
}
