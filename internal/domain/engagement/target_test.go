package engagement_test

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestInferTargetKind(t *testing.T) {
	cases := []struct {
		in   string
		want engagement.TargetKind
	}{
		{"app.example.com", engagement.TargetDomain},
		{"https://app.example.com/login", engagement.TargetURL},
		{"10.0.0.5", engagement.TargetIP},
		{"2001:db8::1", engagement.TargetIP},
		{"10.0.0.0/24", engagement.TargetCIDR},
		{"  example.com  ", engagement.TargetDomain}, // trimmed
		{"not/a/cidr", engagement.TargetDomain},      // slash but not a prefix
	}
	for _, tc := range cases {
		if got := engagement.InferTargetKind(tc.in); got != tc.want {
			t.Errorf("InferTargetKind(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestValidateTargetValue(t *testing.T) {
	ok := []string{"app.example.com", "10.0.0.0/24", "https://x.io/a"}
	for _, v := range ok {
		if err := engagement.ValidateTargetValue(v); err != nil {
			t.Errorf("ValidateTargetValue(%q) unexpected error: %v", v, err)
		}
	}
	bad := []string{"", "-rf", "--config=x", "has space", "tab\there", "line\nbreak"}
	for _, v := range bad {
		if err := engagement.ValidateTargetValue(v); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("ValidateTargetValue(%q) = %v, want ErrValidation", v, err)
		}
	}
}
