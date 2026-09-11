package secretverify

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeRawResolver struct{ raw map[string]string }

func (r fakeRawResolver) VisitRawSecret(_ context.Context, _ string, hit ports.SecretRawFinding, visit func(string) error) (bool, error) {
	value, ok := r.raw[verificationKey(hit)]
	if !ok {
		return false, nil
	}
	return true, visit(value)
}

func newTestVerifier(server *httptest.Server, raw map[string]string) *Verifier {
	return &Verifier{
		resolver:           fakeRawResolver{raw: raw},
		public:             server.Client(),
		vault:              server.Client(),
		github:             server.URL + "/user",
		githubInstallation: server.URL + "/installation/repositories",
		sts:                server.URL + "/sts",
		vaultURL:           server.URL + "/v1/auth/token/lookup-self",
		max:                defaultMaxChecks,
		now:                func() time.Time { return time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC) },
	}
}

func rawKey(file string, line int, rule string) string {
	return verificationKey(ports.SecretRawFinding{File: file, Line: line, RuleID: rule})
}

func TestVerifierGitHubVerifiedNeverReturnsCredential(t *testing.T) {
	token := "ghp_" + strings.Repeat("aB3dE6", 7)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Fatalf("authorization header mismatch")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"login":"private-account-data"}`)
	}))
	defer server.Close()

	hit := ports.SecretRawFinding{File: "config.env", Line: 3, RuleID: "github-token", Match: "ghp_****"}
	v := newTestVerifier(server, map[string]string{rawKey(hit.File, hit.Line, hit.RuleID): token})
	results, err := v.Verify(context.Background(), t.TempDir(), []ports.SecretRawFinding{hit})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Status != ports.SecretVerificationVerified || results[0].Provider != providerGitHub {
		t.Fatalf("results = %#v", results)
	}
	if strings.Contains(fmt.Sprintf("%#v", results), token) || strings.Contains(results[0].Reason, "private-account-data") {
		t.Fatal("verification result leaked provider or credential material")
	}
}

func TestVerifierGitHubRejectedAndRateLimited(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	hit1 := ports.SecretRawFinding{File: "a.env", Line: 1, RuleID: "github-token"}
	hit2 := ports.SecretRawFinding{File: "b.env", Line: 1, RuleID: "github-fine-grained-pat"}
	v := newTestVerifier(server, map[string]string{
		rawKey(hit1.File, hit1.Line, hit1.RuleID): "ghp_" + strings.Repeat("a", 40),
		rawKey(hit2.File, hit2.Line, hit2.RuleID): "github_pat_" + strings.Repeat("b", 40),
	})
	results, err := v.Verify(context.Background(), ".", []ports.SecretRawFinding{hit1, hit2})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].Status != ports.SecretVerificationUnverified || results[1].Status != ports.SecretVerificationUnknown {
		t.Fatalf("results = %#v", results)
	}
	if results[1].Reason != reasonRateLimited {
		t.Fatalf("rate-limit reason = %q", results[1].Reason)
	}
}

func TestVerifierGitHubRefreshTokenIsUnknownWithoutNetwork(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()

	hit := ports.SecretRawFinding{File: "oauth.env", Line: 1, RuleID: "github-token"}
	token := "ghr_" + strings.Repeat("a", 40)
	v := newTestVerifier(server, map[string]string{rawKey(hit.File, hit.Line, hit.RuleID): token})
	results, err := v.Verify(context.Background(), ".", []ports.SecretRawFinding{hit})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 || len(results) != 1 || results[0].Status != ports.SecretVerificationUnknown || results[0].Reason != reasonUnsupported {
		t.Fatalf("calls=%d results=%#v", calls.Load(), results)
	}
}

func TestVerifierGitHubInstallationTokenUsesInstallationEndpoint(t *testing.T) {
	token := "ghs_" + strings.Repeat("a", 40)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/installation/repositories" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Fatalf("authorization header mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hit := ports.SecretRawFinding{File: "app.env", Line: 1, RuleID: "github-token"}
	v := newTestVerifier(server, map[string]string{rawKey(hit.File, hit.Line, hit.RuleID): token})
	results, err := v.Verify(context.Background(), ".", []ports.SecretRawFinding{hit})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Status != ports.SecretVerificationVerified || results[0].Provider != providerGitHub {
		t.Fatalf("results=%#v", results)
	}
}

func TestVerifierVaultLookupSelf(t *testing.T) {
	token := "hvs." + strings.Repeat("Ab3", 16)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/lookup-self" || r.Header.Get("X-Vault-Token") != token {
			t.Fatalf("unexpected vault request")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hit := ports.SecretRawFinding{File: "vault.env", Line: 1, RuleID: "vault-token"}
	v := newTestVerifier(server, map[string]string{rawKey(hit.File, hit.Line, hit.RuleID): token})
	results, err := v.Verify(context.Background(), ".", []ports.SecretRawFinding{hit})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Status != ports.SecretVerificationVerified || results[0].Provider != providerVault {
		t.Fatalf("results = %#v", results)
	}
}

func TestVerifierAWSUsesOneSignedGetCallerIdentityRequest(t *testing.T) {
	access := "AKIA" + "Z2K7QMN4TJ5VWXY9"
	secret := "aB3dE6fG9hJ2kL5mN8pQ1rS4tU7vW0xY3zA6bC9d"
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		allHeaders := fmt.Sprint(r.Header)
		if strings.Contains(string(body), secret) || strings.Contains(allHeaders, secret) {
			t.Fatal("AWS secret access key was transmitted instead of being used only for signing")
		}
		if !strings.Contains(r.Header.Get("Authorization"), "Credential="+access+"/") {
			t.Fatalf("missing SigV4 access-key credential: %q", r.Header.Get("Authorization"))
		}
		if string(body) != "Action=GetCallerIdentity&Version=2011-06-15" {
			t.Fatalf("body = %q", body)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `<GetCallerIdentityResponse/>`)
	}))
	defer server.Close()

	idHit := ports.SecretRawFinding{File: "aws.env", Line: 2, RuleID: "aws-access-key-id"}
	secretHit := ports.SecretRawFinding{File: "aws.env", Line: 3, RuleID: "aws-secret-access-key"}
	v := newTestVerifier(server, map[string]string{
		rawKey(idHit.File, idHit.Line, idHit.RuleID):             access,
		rawKey(secretHit.File, secretHit.Line, secretHit.RuleID): secret,
	})
	results, err := v.Verify(context.Background(), ".", []ports.SecretRawFinding{idHit, secretHit})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("STS calls = %d, want 1", calls.Load())
	}
	if len(results) != 2 {
		t.Fatalf("results = %#v", results)
	}
	for _, result := range results {
		if result.Status != ports.SecretVerificationVerified || result.Provider != providerAWS {
			t.Fatalf("result = %#v", result)
		}
	}
	if strings.Contains(fmt.Sprintf("%#v", results), secret) {
		t.Fatal("verification results leaked AWS secret access key")
	}
}

func TestVerifierAWSMissingPairIsUnknownWithoutNetwork(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	hit := ports.SecretRawFinding{File: "aws.env", Line: 1, RuleID: "aws-access-key-id"}
	v := newTestVerifier(server, map[string]string{rawKey(hit.File, hit.Line, hit.RuleID): "AKIA" + strings.Repeat("A", 16)})
	results, err := v.Verify(context.Background(), ".", []ports.SecretRawFinding{hit})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 || len(results) != 1 || results[0].Status != ports.SecretVerificationUnknown || results[0].Reason != reasonMissingPair {
		t.Fatalf("calls=%d results=%#v", calls.Load(), results)
	}
}

func TestVerifierAWSAmbiguousPairIsUnknownWithoutNetwork(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()

	idHit := ports.SecretRawFinding{File: "aws.env", Line: 10, RuleID: "aws-access-key-id"}
	secretA := ports.SecretRawFinding{File: "aws.env", Line: 11, RuleID: "aws-secret-access-key"}
	secretB := ports.SecretRawFinding{File: "aws.env", Line: 20, RuleID: "aws-secret-access-key"}
	v := newTestVerifier(server, map[string]string{
		rawKey(idHit.File, idHit.Line, idHit.RuleID):       "AKIA" + strings.Repeat("A", 16),
		rawKey(secretA.File, secretA.Line, secretA.RuleID): strings.Repeat("aB3dE6fG", 5),
		rawKey(secretB.File, secretB.Line, secretB.RuleID): strings.Repeat("hJ2kL5mN", 5),
	})
	results, err := v.Verify(context.Background(), ".", []ports.SecretRawFinding{idHit, secretA, secretB})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatalf("STS calls = %d, want 0 for ambiguous pairing", calls.Load())
	}
	if len(results) != 3 {
		t.Fatalf("results = %#v", results)
	}
	for _, result := range results {
		if result.Status != ports.SecretVerificationUnknown || result.Reason != reasonMissingPair {
			t.Fatalf("ambiguous result = %#v", result)
		}
	}
}
