package config

import "testing"

func TestSecretVerificationDefaultOff(t *testing.T) {
	t.Setenv("SYNAPSE_SECRET_VERIFY_ENABLED", "")
	t.Setenv("SYNAPSE_SECRET_VERIFY_VAULT_ADDR", "")
	settings := (Config{}).SecretVerification()
	if settings.Enabled {
		t.Fatal("active secret verification must be default-off")
	}
	if settings.VaultAddr != "" {
		t.Fatalf("vault addr = %q, want empty", settings.VaultAddr)
	}
}

func TestSecretVerificationReadsOptInSettings(t *testing.T) {
	t.Setenv("SYNAPSE_SECRET_VERIFY_ENABLED", "true")
	t.Setenv("SYNAPSE_SECRET_VERIFY_VAULT_ADDR", " https://vault.internal:8200/ ")
	settings := (Config{}).SecretVerification()
	if !settings.Enabled {
		t.Fatal("expected active verification enabled")
	}
	if settings.VaultAddr != "https://vault.internal:8200/" {
		t.Fatalf("vault addr = %q", settings.VaultAddr)
	}
}

func TestValidateSecretVerification(t *testing.T) {
	tests := []struct {
		name    string
		enabled string
		vault   string
		wantErr bool
	}{
		{name: "disabled ignores endpoint", enabled: "false", vault: "http://vault.internal", wantErr: false},
		{name: "enabled without Vault", enabled: "true", vault: "", wantErr: false},
		{name: "valid HTTPS Vault", enabled: "true", vault: "https://vault.internal:8200", wantErr: false},
		{name: "HTTP Vault rejected", enabled: "true", vault: "http://vault.internal", wantErr: true},
		{name: "userinfo rejected", enabled: "true", vault: "https://user@vault.internal", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SYNAPSE_SECRET_VERIFY_ENABLED", tt.enabled)
			t.Setenv("SYNAPSE_SECRET_VERIFY_VAULT_ADDR", tt.vault)
			err := (Config{}).ValidateSecretVerification()
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateSecretVerification() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
