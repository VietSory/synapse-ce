package jsresolve

import (
	"strings"
	"testing"
)

func TestMaintainerAuditStrictJSONNestingDepthIsBounded(t *testing.T) {
	t.Parallel()
	const depth = 512
	raw := []byte(strings.Repeat("[", depth) + "0" + strings.Repeat("]", depth))
	if err := validateNoDuplicateJSONKeys(raw); err == nil {
		t.Fatal("deeply nested metadata JSON was accepted without a nesting budget")
	}
}
