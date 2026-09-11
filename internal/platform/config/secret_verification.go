package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// SecretVerificationSettings is the opt-in network lane for checking whether a detected provider credential
// is currently usable. It is deliberately separate from SecretScanEnabled: deterministic detection remains
// offline/read-only unless an operator explicitly enables active verification.
type SecretVerificationSettings struct {
	Enabled   bool
	VaultAddr string
}

// SecretVerification returns the active-secret verification settings. Environment is read only at composition
// time; callers should retain the returned snapshot for the lifetime of their service.
func (Config) SecretVerification() SecretVerificationSettings {
	return SecretVerificationSettings{
		Enabled:   getbool("SYNAPSE_SECRET_VERIFY_ENABLED", false),
		VaultAddr: strings.TrimSpace(os.Getenv("SYNAPSE_SECRET_VERIFY_VAULT_ADDR")),
	}
}

// ValidateSecretVerification rejects a malformed optional Vault endpoint before a
// server begins serving scans. An empty endpoint is valid: GitHub and AWS checks
// do not require an operator-supplied URL.
func (c Config) ValidateSecretVerification() error {
	settings := c.SecretVerification()
	if !settings.Enabled || settings.VaultAddr == "" {
		return nil
	}
	u, err := url.Parse(settings.VaultAddr)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return fmt.Errorf("SYNAPSE_SECRET_VERIFY_VAULT_ADDR must be an https URL without userinfo")
	}
	return nil
}
