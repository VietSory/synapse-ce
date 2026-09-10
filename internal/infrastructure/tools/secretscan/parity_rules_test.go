package secretscan

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestParityExpansionRules(t *testing.T) {
	assign := func(key string, parts ...string) string { return key + `="` + strings.Join(parts, "") + `"` }
	join := func(parts ...string) string { return strings.Join(parts, "") }
	tests := []struct {
		id       string
		positive string
		negative string
	}{
		{"okta-api-token", assign("OKTA_API_TOKEN", "00AbCdEfGhIjKlMn", "OpQrStUvWxYz123456"), assign("OKTA_API_TOKEN", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE1234")},
		{"auth0-client-secret", assign("AUTH0_CLIENT_SECRET", "aB3dE5fG7hJ9kL2m", "N4pQ6rS8tU0vW1xY3zA5bC7d"), assign("AUTH0_CLIENT_SECRET", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE1234")},
		{"cloudflare-api-token", assign("CLOUDFLARE_API_TOKEN", "Ab3dE5fG7hJ9kL2m", "N4pQ6rS8tU0vW1xY"), assign("CLOUDFLARE_API_TOKEN", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE1234")},
		{"cloudflare-global-api-key", assign("CF_GLOBAL_API_KEY", "A1b2C3d4E5f6G7h8", "I9j0K1l2M3n4O5p6"), assign("CF_GLOBAL_API_KEY", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE1234")},
		{"firebase-server-key", assign("FIREBASE_SERVER_KEY", "AAAA0AbCdEfGhIjKlMnOpQrSt", "UvWxYz1234567890:APA91b"), assign("FIREBASE_SERVER_KEY", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLEEXAMPLE")},
		{"discord-bot-token", assign("DISCORD_BOT_TOKEN", "AbCdEfGhIjKlMnOpQrStUvWx", ".Yz1234.", "AbCdEfGhIjKlMnOpQrStUvWxYz1234"), assign("DISCORD_BOT_TOKEN", "EXAMPLEEXAMPLEEXAMPLEEXAM", ".Yz1234.", "EXAMPLEEXAMPLEEXAMPLEEXAMPLE12")},
		{"heroku-api-key", assign("HEROKU_API_KEY", "Ab3dE5fG7hJ9kL2m", "N4pQ6rS8tU0vW1xY"), assign("HEROKU_API_KEY", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE1234")},
		{"mapbox-secret-token", assign("MAPBOX_SECRET_TOKEN", "sk.", "Ab3dE5fG7hJ9kL2m", "N4pQ6rS8tU0vW1xY3zA5"), assign("MAPBOX_SECRET_TOKEN", "sk.", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLEEXAMPLE")},
		{"netlify-access-token", assign("NETLIFY_ACCESS_TOKEN", "Ab3dE5fG7hJ9kL2m", "N4pQ6rS8tU0vW1xY3zA5"), assign("NETLIFY_ACCESS_TOKEN", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE1234")},
		{"pagerduty-api-token", assign("PAGERDUTY_API_TOKEN", "A1b2C3d4E5f6G7h8", "I9j0K1l2M3n4O5p6"), assign("PAGERDUTY_API_TOKEN", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE1234")},
		{"snyk-api-token", assign("SNYK_API_TOKEN", "a1b2c3d4-e5f6-47a8-", "91b2-c3d4e5f6a7b8"), assign("SNYK_API_TOKEN", "EXAMPLE-EXAMPLE-", "EXAMPLE-EXAMPLE123456")},
		{"twitter-bearer-token", assign("TWITTER_BEARER_TOKEN", "AAAAA1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6"), assign("TWITTER_BEARER_TOKEN", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE")},
		{"azure-ad-client-secret", assign("ENTRA_CLIENT_SECRET", "A1b2C3d4E5f6.G7h8-", "I9j0_K1l2M3n4O5p6Q7r8"), assign("ENTRA_CLIENT_SECRET", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE1234")},
		{"aws-session-token", assign("AWS_SESSION_TOKEN", "IQoJb3JpZ2luX2VjEAkaCXVzLWVhc3Qt", "MSJHMEUCIQDfAbCdEfGhIjKlMnOpQrSt", "UvWxYz1234567890+/AaBbCcDdEeFfGgHh"), assign("AWS_SESSION_TOKEN", strings.Repeat("EXAMPLE", 14))},
		{"gcp-oauth-client-secret", join("client_secret=\"", "GOCSPX-", "AbCdEfGhIjKlMnOpQrStUvWxYz1234", "\""), join("client_secret=\"", "GOCSPX-", "EXAMPLEEXAMPLEEXAMPLEEXAMPLE", "\"")},
		{"kubeconfig-token", join("token: ", "eyJhbGciOiJSUzI1NiJ9.", "AbCdEfGhIjKlMnOpQrStUvWxYz.", "0123456789abcdef"), "token: EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE"},
		{"authorization-bearer", join("Authorization: Bearer ", "AbCdEfGhIjKlMnOp", "QrStUvWxYz1234567890"), "Authorization: Bearer EXAMPLEEXAMPLEEXAMPLEEXAMPLE1234"},
		{"authorization-basic", join("Authorization: Basic ", "QWxhZGRpbjpvcGVu", "IHNlc2FtZTEyMzQ1Njc4OTA="), "Authorization: Basic EXAMPLEEXAMPLEEXAMPLEEXAMPLE"},
		{"npmrc-auth-token", join("//registry.npmjs.org/:_authToken=", "AbCdEfGhIjKlMnOp", "QrStUvWxYz123456"), "//registry.npmjs.org/:_authToken=EXAMPLEEXAMPLEEXAMPLEEXAMPLE"},
		{"pypirc-password", join("[pypi]\nusername = __token__\npassword = ", "AbCdEfGhIjKlMnOp", "QrStUvWxYz123456"), "[pypi]\nusername = __token__\npassword = EXAMPLEEXAMPLEEXAMPLEEXAMPLE"},
		{"netrc-password", join("machine api.example.net login buildbot password ", "AbCdEfGhIjKlMnOp", "QrSt1234"), "machine api.example.net login buildbot password EXAMPLEEXAMPLEEXAMPLE"},
		{"htpasswd-hash", join("alice:", "$apr1$", "12345678$", "abcdefghijklmnopqrstuv"), join("alice:", "$apr1$", "example1$", "abcdefghijklmnopqrstuv")},
		{"circleci-token", assign("CIRCLECI_TOKEN", "AbCdEfGhIjKlMnOp", "QrStUvWxYz123456"), assign("CIRCLECI_TOKEN", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE")},
		{"bitbucket-app-password", assign("BITBUCKET_APP_PASSWORD", "AbCdEfGhIjKlMnOp", "QrStUvWxYz123456"), assign("BITBUCKET_APP_PASSWORD", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE")},
		{"azure-devops-pat", assign("AZDO_PAT", "Ab3dE5gH7jK9m", "Ab3dE5gH7jK9m", "Ab3dE5gH7jK9m", "Ab3dE5gH7jK9m"), assign("AZDO_PAT", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE1234")},
		{"fastly-api-token", assign("FASTLY_API_TOKEN", "AbCdEfGhIjKlMnOp", "QrStUvWxYz123456"), assign("FASTLY_API_TOKEN", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE")},
		{"vercel-token", assign("VERCEL_ACCESS_TOKEN", "AbCdEfGhIjKlMnOp", "QrStUvWxYz123456"), assign("VERCEL_ACCESS_TOKEN", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE")},
		{"supabase-service-role-key", assign("SUPABASE_SERVICE_ROLE_KEY", "eyJhbGciOiJIUzI1NiJ9.", "AbCdEfGhIjKlMnOpQrStUvWx.", "Yz1234567890AbCdEfGhIjKl"), assign("SUPABASE_SERVICE_ROLE_KEY", "EXAMPLEEXAMPLEEXAMPLEEX.", "EXAMPLEEXAMPLEEXAMPLE.", "EXAMPLEEXAMPLEEXAMPLE")},
		{"algolia-admin-api-key", assign("ALGOLIA_ADMIN_API_KEY", "a1b2c3d4e5f67890", "123456789abcdef0"), assign("ALGOLIA_ADMIN_API_KEY", strings.Repeat("0", 32))},
		{"launchdarkly-sdk-key", assign("LD_SDK_KEY", "sdk-AbCdEfGhIjKlMnOp", "QrStUvWxYz123456"), assign("LD_SDK_KEY", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE")},
		{"launchdarkly-api-token", assign("LD_API_TOKEN", "api-AbCdEfGhIjKlMnOp", "QrStUvWxYz123456"), assign("LD_API_TOKEN", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE")},
		{"segment-write-key", assign("SEGMENT_WRITE_KEY", "AbCdEfGhIjKlMnOp", "QrStUvWxYz123456"), assign("SEGMENT_WRITE_KEY", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE")},
		{"posthog-api-key", assign("POSTHOG_API_KEY", "phx_", "AbCdEfGhIjKlMnOp", "QrStUvWxYz123456"), assign("POSTHOG_API_KEY", "phx_", "EXAMPLEEXAMPLEEXAMPLE")},
		{"datadog-application-key", assign("DD_APPLICATION_KEY", "a1b2c3d4e5f67890", "123456789abcdef0", "a1b2c3d4"), assign("DD_APPLICATION_KEY", strings.Repeat("0", 40))},
		{"honeycomb-api-key", assign("HONEYCOMB_API_KEY", "AbCdEfGhIjKlMnOp", "QrStUvWxYz123456"), assign("HONEYCOMB_API_KEY", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE")},
		{"splunk-hec-token", assign("SPLUNK_HEC_TOKEN", "a1b2c3d4-e5f6-47a8-", "91b2-c3d4e5f6a7b8"), assign("SPLUNK_HEC_TOKEN", "EXAMPLE-EXAMPLE-", "EXAMPLE-EXAMPLE123456")},
		{"elastic-api-key", join("Authorization: ApiKey ", "QWJDREVGR0hJSktM", "TU5PUFFSU1RVVldYWVo="), "Authorization: ApiKey EXAMPLEEXAMPLEEXAMPLEEXAMPLE"},
		{"jenkins-api-token", assign("JENKINS_API_TOKEN", "a1b2c3d4e5f67890", "123456789abcdef0"), assign("JENKINS_API_TOKEN", strings.Repeat("0", 32))},
		{"travis-ci-token", assign("TRAVIS_CI_TOKEN", "AbCdEfGhIjKlMnOp", "QrStUvWxYz123456"), assign("TRAVIS_CI_TOKEN", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE")},
		{"github-client-secret", assign("GITHUB_CLIENT_SECRET", "a1b2c3d4e5f67890", "123456789abcdef0", "a1b2c3d4"), assign("GITHUB_CLIENT_SECRET", strings.Repeat("0", 40))},
		{"gitlab-deploy-token", join("token=\"", "gldt-", "AbCdEfGhIjKlMnOpQrStUvWx", "\""), join("token=\"", "gldt-", "EXAMPLEEXAMPLEEXAMPLEEXAMPLE", "\"")},
		{"shopify-shared-secret", assign("SHOPIFY_SHARED_SECRET", "a1b2c3d4e5f67890", "123456789abcdef0"), assign("SHOPIFY_SHARED_SECRET", strings.Repeat("0", 32))},
		{"azure-sas-token", assign("AZURE_SAS_TOKEN", "?sv=2024-11-04&ss=b&srt=sco&sp=rwdlacupiytfx&sig=", "AbCdEfGhIjKlMnOpQrStUvWxYz123456"), assign("AZURE_SAS_TOKEN", "?sv=2024-11-04&sig=", "EXAMPLEEXAMPLEEXAMPLEEXAMPLE")},
		{"gcp-oauth-refresh-token", join("refresh_token=\"", "1//", "0gAbCdEfGhIjKlMnOpQrStUvWxYz1234567890", "\""), join("refresh_token=\"", "1//", "EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE", "\"")},
		{"mongodb-atlas-api-private-key", assign("MONGODB_ATLAS_PRIVATE_KEY", "AbCdEfGhIjKlMnOp", "QrStUvWxYz123456"), assign("MONGODB_ATLAS_PRIVATE_KEY", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE")},
	}

	if got := len(defaultRules()); got < 120 {
		t.Fatalf("default secret detector count = %d, want at least 120", got)
	}
	if got := len(parityExpansionRules()); got != len(tests) {
		t.Fatalf("expansion rule count = %d, fixture count = %d", got, len(tests))
	}

	s := New()
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if !scanHasRule(s, tt.positive, tt.id) {
				t.Fatalf("positive fixture did not trigger %s", tt.id)
			}
			if scanHasRule(s, tt.negative, tt.id) {
				t.Fatalf("placeholder negative triggered %s", tt.id)
			}
		})
	}
}

func scanHasRule(s *Scanner, text, want string) bool {
	var findings []ports.SecretRawFinding
	s.scanContent("fixture.env", []byte(text), map[string]bool{}, &findings, 1000)
	for _, finding := range findings {
		if finding.RuleID == want {
			return true
		}
	}
	return false
}

func TestParityExpansionRuleIDsUnique(t *testing.T) {
	ids := parityExpansionRuleIDs()
	for i := 1; i < len(ids); i++ {
		if ids[i] == ids[i-1] {
			t.Fatalf("duplicate parity expansion rule id %q", ids[i])
		}
	}
	if len(ids) != 45 {
		t.Fatalf("parity expansion rule count = %d, want 45", len(ids))
	}
	for _, id := range ids {
		if strings.TrimSpace(id) == "" {
			t.Fatal("empty parity expansion rule id")
		}
	}
}
