package config

import "testing"

// TestIsProductionFailsClosed pins the env-gate hardening: IsProduction normalizes
// (trim + lowercase) and treats anything that is NOT an explicitly recognized
// non-production environment as production, so a misconfigured/misspelled env lands in
// the strict security gates (vault key, signing, sandbox) instead of silently failing
// open to ephemeral-key dev behavior. No caller may compare cfg.Environment directly.
func TestIsProductionFailsClosed(t *testing.T) {
	production := []string{
		"production", "Production", "PRODUCTION", " production ", "production\n",
		"prod", "PROD", "staging", "preprod", "prdo", "typo-env", "",
	}
	for _, e := range production {
		if !(Config{Environment: e}).IsProduction() {
			t.Errorf("env %q must be treated as production (fail closed)", e)
		}
	}
	nonProduction := []string{"development", "DEVELOPMENT", " dev ", "dev", "local", "test", "ci"}
	for _, e := range nonProduction {
		if (Config{Environment: e}).IsProduction() {
			t.Errorf("env %q must be treated as non-production", e)
		}
	}
}

// TestLoadNormalizesEnvironment confirms Load canonicalizes the env so logs + any reader
// see one form.
func TestLoadNormalizesEnvironment(t *testing.T) {
	t.Setenv("SYNAPSE_ENV", "  Production  ")
	if got := Load().Environment; got != "production" {
		t.Fatalf("Load must normalize SYNAPSE_ENV to %q, got %q", "production", got)
	}
}

// TestFindingMinSeverityDefaultsToInfo pins the default vuln severity floor at "info" so EVERY
// detected vulnerability is promoted to a finding (matching Grype/Trivy/OSV-Scanner). A higher
// default silently hides detected vulns and reads as "missing vulns"; prioritization is by risk
// priority (KEV→EPSS×CVSS), not by dropping findings. Do not raise this default.
func TestFindingMinSeverityDefaultsToInfo(t *testing.T) {
	t.Setenv("SYNAPSE_FINDING_MIN_SEVERITY", "")
	if got := Load().FindingMinSeverity; got != "info" {
		t.Fatalf("default FindingMinSeverity = %q, want \"info\" (promote all detected vulns)", got)
	}
	t.Setenv("SYNAPSE_FINDING_MIN_SEVERITY", "high")
	if got := Load().FindingMinSeverity; got != "high" {
		t.Fatalf("override = %q, want \"high\"", got)
	}
}

// TestLoadReachability confirms the Tier-2 reachability proof is OFF by default (opt-in) and the
// govulncheck binary defaults sensibly.
func TestLoadReachability(t *testing.T) {
	t.Setenv("SYNAPSE_REACHABILITY_ENABLED", "")
	t.Setenv("SYNAPSE_GOVULNCHECK_BIN", "") // hermetic: ignore any binary override in the runner env
	if c := Load(); c.ReachabilityEnabled {
		t.Error("reachability must be OFF by default (opt-in)")
	}
	if got := Load().GovulncheckBin; got != "govulncheck" {
		t.Errorf("GovulncheckBin default = %q, want govulncheck", got)
	}
	t.Setenv("SYNAPSE_REACHABILITY_ENABLED", "true")
	if !Load().ReachabilityEnabled {
		t.Error("SYNAPSE_REACHABILITY_ENABLED=true must enable it")
	}
}

// TestLoadSBOMProducer confirms the SBOM producer defaults to syft and honors the env override.
func TestLoadSBOMProducer(t *testing.T) {
	t.Setenv("SYNAPSE_SBOM_PRODUCER", "")
	if got := Load().SBOMProducer; got != "syft" {
		t.Errorf("SBOMProducer default = %q, want syft", got)
	}
	t.Setenv("SYNAPSE_SBOM_PRODUCER", "ownsbom")
	if got := Load().SBOMProducer; got != "ownsbom" {
		t.Errorf("SBOMProducer from env = %q, want ownsbom", got)
	}
}

// TestLoadMaxWorkspaceBytes confirms the acquire workspace cap defaults to 2 GiB and honors a
// byte override (including values beyond int32) via SYNAPSE_MAX_WORKSPACE_BYTES.
func TestLoadMaxWorkspaceBytes(t *testing.T) {
	t.Setenv("SYNAPSE_MAX_WORKSPACE_BYTES", "")
	if got := Load().MaxWorkspaceBytes; got != 2<<30 {
		t.Errorf("MaxWorkspaceBytes default = %d, want %d", got, int64(2<<30))
	}
	t.Setenv("SYNAPSE_MAX_WORKSPACE_BYTES", "8589934592") // 8 GiB, exceeds int32
	if got := Load().MaxWorkspaceBytes; got != 8589934592 {
		t.Errorf("MaxWorkspaceBytes from env = %d, want 8589934592", got)
	}
}
