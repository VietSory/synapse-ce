package ports

import (
	"context"
	"strings"
)

// SecretVerificationStatus is the closed result vocabulary for an active, read-only credential check.
// Verification is evidence about whether a leaked credential is usable NOW; it never erases the underlying
// presence finding because a revoked credential was still committed and must still be removed/rotated.
type SecretVerificationStatus string

const (
	SecretVerificationVerified   SecretVerificationStatus = "verified"
	SecretVerificationUnverified SecretVerificationStatus = "unverified"
	SecretVerificationUnknown    SecretVerificationStatus = "unknown"
)

// Valid reports whether s is a known verification status.
func (s SecretVerificationStatus) Valid() bool {
	switch s {
	case SecretVerificationVerified, SecretVerificationUnverified, SecretVerificationUnknown:
		return true
	}
	return false
}

// SecretVerification is the scrubbed result of one active credential check. It deliberately contains no
// credential, request headers, response body, upstream error text, account identity, or tenant/provider data.
// Provider and Reason are bounded adapter-owned tokens suitable for deterministic finding provenance.
type SecretVerification struct {
	File     string
	Line     int
	RuleID   string
	Status   SecretVerificationStatus
	Provider string
	Reason   string
}

// Valid reports whether the scrubbed verification result is safe to cross the infrastructure/use-case trust
// boundary. Provider and Reason are intentionally restricted to short machine tokens: upstream text must never
// leak into a finding, report, audit entry, or evidence seal through this DTO.
func (v SecretVerification) Valid() bool {
	if strings.TrimSpace(v.File) == "" || v.Line <= 0 || strings.TrimSpace(v.RuleID) == "" || !v.Status.Valid() {
		return false
	}
	return safeVerificationToken(v.Provider, 64) && safeVerificationToken(v.Reason, 128)
}

func safeVerificationToken(value string, max int) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > max {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

// SecretVerifier actively checks supported redacted secret findings using the minimum read-only provider
// request. root is the already-authorized prepared workspace. Implementations may transiently recover the raw
// credential from root, but MUST NOT return, persist, or log it. Unsupported findings return no result; provider
// outage/rate-limit/ambiguous material returns Status=unknown rather than failing the whole scan.
type SecretVerifier interface {
	Verify(ctx context.Context, root string, findings []SecretRawFinding) ([]SecretVerification, error)
}

// SecretVerificationScanner is the opt-in extension consumed by the SCA pipeline. It keeps deterministic
// presence detection (`SecretScanner`) separate from network authority while returning verification evidence in
// the same call, so no mutable per-scan side channel is needed. Implementations must retain every base finding.
type SecretVerificationScanner interface {
	SecretScanner
	ScanFilesVerified(ctx context.Context, root string) (SecretScanReport, []SecretVerification, error)
}
