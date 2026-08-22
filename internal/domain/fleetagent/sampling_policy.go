package fleetagent

import (
	"bytes"
	"fmt"
)

// SamplingPolicyDigest commits the complete sampling-policy tuple named by A3.
// Length-prefixing every field makes the commitment unambiguous without relying
// on JSON key ordering or whitespace, and keeps future policy changes explicit.
func SamplingPolicyDigest(algorithm, policyID, seed string, version uint64) (string, error) {
	if algorithm == "" || policyID == "" || version == 0 {
		return "", fmt.Errorf("sampling policy commitment requires algorithm, policy id and positive version")
	}
	var buf bytes.Buffer
	writeCommitString(&buf, "synapse-sampling-policy:v1")
	writeCommitString(&buf, algorithm)
	writeCommitString(&buf, policyID)
	writeCommitString(&buf, seed)
	writeCommitUint64(&buf, version)
	return SHA256Hex(buf.Bytes()), nil
}
