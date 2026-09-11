package sca

import (
	"sort"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// #nosec G101 -- provider label only; this is not a credential or credential-shaped test fixture.
const secretVerificationSourcePrefix = "synapse-secret-verify/"

// applySecretVerification projects scrubbed provider evidence onto already-built secret presence findings.
// It is retain-and-mark by construction: no verification state ever removes a finding. Verified credentials
// become high-confidence and are removed from the needs-verify queue; unverified/unknown credentials stay
// reported and evidence-sealed but are routed to that queue for human follow-up. Unsupported secrets (no
// verification result) keep the legacy behaviour unchanged.
func applySecretVerification(result *ScanResult, raws []ports.SecretRawFinding, verifications []ports.SecretVerification) {
	if result == nil || len(verifications) == 0 {
		return
	}
	// Keep only DTOs that satisfy the trust-boundary validation, then seal the same scrubbed values in ScanResult.
	valid := make([]ports.SecretVerification, 0, len(verifications))
	for _, verification := range verifications {
		if verification.Valid() { valid = append(valid, verification) }
	}
	sort.Slice(valid, func(i, j int) bool {
		left, right := secretVerificationKey(valid[i].RuleID, valid[i].File, valid[i].Line), secretVerificationKey(valid[j].RuleID, valid[j].File, valid[j].Line)
		if left != right { return left < right }
		return valid[i].Provider < valid[j].Provider
	})
	result.SecretVerifications = valid
	if len(result.Findings) == 0 { return }

	known := make(map[string]ports.SecretRawFinding, len(raws))
	for _, raw := range raws {
		if raw.FromHistory {
			continue
		}
		known[secretVerificationKey(raw.RuleID, raw.File, raw.Line)] = raw
	}

	findingByDedup := make(map[string]int, len(result.Findings))
	for i := range result.Findings {
		if result.Findings[i].Kind == finding.KindSecret {
			findingByDedup[result.Findings[i].DedupKey] = i
		}
	}

	for _, verification := range verifications {
		if !verification.Valid() {
			continue
		}
		raw, ok := known[secretVerificationKey(verification.RuleID, verification.File, verification.Line)]
		if !ok {
			continue // a verifier cannot manufacture a finding the deterministic scanner did not emit
		}
		dedup := secretDedupKey(raw)
		index, ok := findingByDedup[dedup]
		if !ok {
			continue // e.g. a test/docs secret suppressed by policy before finding projection
		}
		item := &result.Findings[index]
		appendFindingSource(item, secretVerificationSourcePrefix+verification.Provider)

		switch verification.Status {
		case ports.SecretVerificationVerified:
			item.Confidence = vulnerability.ConfidenceHigh
			appendSecretVerificationNote(item, "Active verification: credential accepted by "+verification.Provider+" using a read-only provider check.")
			removeNeedsVerification(result, dedup)
		case ports.SecretVerificationUnverified:
			appendSecretVerificationNote(item, "Active verification: credential rejected by "+verification.Provider+" at scan time; leaked-secret presence still requires remediation.")
			upsertSecretNeedsVerification(result, *item, "Active verification rejected the credential at scan time; verify rotation/revocation before closing the finding.")
		case ports.SecretVerificationUnknown:
			appendSecretVerificationNote(item, "Active verification: credential status could not be established by "+verification.Provider+"; leaked-secret presence still requires remediation.")
			upsertSecretNeedsVerification(result, *item, "Active verification could not establish credential status; verify before acting.")
		}
	}
}

func secretVerificationKey(ruleID, file string, line int) string {
	return ruleID + "\x00" + file + "\x00" + strconv.Itoa(line)
}

func secretDedupKey(raw ports.SecretRawFinding) string {
	return "secret:" + raw.RuleID + ":" + raw.File + ":" + strconv.Itoa(raw.Line)
}

func appendFindingSource(item *finding.Finding, source string) {
	if item == nil || strings.TrimSpace(source) == "" {
		return
	}
	for _, existing := range item.Sources {
		if existing == source {
			return
		}
	}
	item.Sources = append(item.Sources, source)
}

func appendSecretVerificationNote(item *finding.Finding, note string) {
	if item == nil || strings.TrimSpace(note) == "" || strings.Contains(item.Description, note) {
		return
	}
	item.Description = strings.TrimSpace(item.Description + "\n" + note)
}

func upsertSecretNeedsVerification(result *ScanResult, item finding.Finding, reason string) {
	for i := range result.NeedsVerification {
		if result.NeedsVerification[i].DedupKey == item.DedupKey {
			result.NeedsVerification[i].Title = item.Title
			result.NeedsVerification[i].Reason = reason
			return
		}
	}
	result.NeedsVerification = append(result.NeedsVerification, NeedsVerifyFinding{
		DedupKey: item.DedupKey,
		Title:    item.Title,
		Reason:   reason,
	})
}

func removeNeedsVerification(result *ScanResult, dedup string) {
	if result == nil || len(result.NeedsVerification) == 0 {
		return
	}
	out := result.NeedsVerification[:0]
	for _, item := range result.NeedsVerification {
		if item.DedupKey != dedup {
			out = append(out, item)
		}
	}
	result.NeedsVerification = out
}
