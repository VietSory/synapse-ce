// Package secretverify performs opt-in, read-only provider checks for secret findings. It never logs or
// returns credential material: the scanner supplies a raw candidate through a callback, the verifier uses it
// for exactly one minimal provider request, and only a closed status/provider/reason tuple crosses back into
// the scan pipeline.
package secretverify

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	defaultMaxChecks    = 32
	maxResponseBytes    = 64 << 10
	publicHTTPTimeout   = 8 * time.Second
	githubUserEndpoint         = "https://api.github.com/user"
	githubInstallationEndpoint = "https://api.github.com/installation/repositories"
	awsSTSEndpoint      = "https://sts.amazonaws.com/"
	providerGitHub      = "github"
	providerAWS         = "aws-sts"
	providerVault       = "vault"
	reasonVerified      = "credential_accepted"
	reasonRejected      = "credential_rejected"
	reasonUnavailable   = "provider_unavailable"
	reasonRateLimited   = "rate_limited"
	reasonMaterial      = "credential_material_unavailable"
	reasonBudget        = "verification_budget_exhausted"
	reasonMissingPair   = "credential_pair_incomplete"
	reasonUnsupported   = "unsupported_candidate"
)

// rawResolver is intentionally a callback seam: the raw secret never becomes a use-case DTO. Scanner
// implementations re-open the already-authorized workspace and invoke visit only for an exact re-match.
type rawResolver interface {
	VisitRawSecret(ctx context.Context, root string, hit ports.SecretRawFinding, visit func(string) error) (bool, error)
}

// Verifier implements ports.SecretVerifier for the provider formats whose liveness can be checked safely.
type Verifier struct {
	resolver rawResolver
	public             *http.Client
	vault              *http.Client
	github             string
	githubInstallation string
	sts                string
	vaultURL           string
	max                int
	now                func() time.Time
}

var _ ports.SecretVerifier = (*Verifier)(nil)

// New builds the production verifier. GitHub and AWS use fixed public endpoints through the shared safe HTTP
// client (no ambient proxy, no redirects, private/link-local destinations rejected). Vault is optional because
// installations commonly have no Vault endpoint; when configured it must be HTTPS and uses a separate client
// that permits RFC1918 addresses while still rejecting loopback/link-local/multicast special ranges.
func New(resolver rawResolver, vaultAddr string) (*Verifier, error) {
	if resolver == nil {
		return nil, fmt.Errorf("secret verifier: nil candidate resolver")
	}
	vaultEndpoint := ""
	if strings.TrimSpace(vaultAddr) != "" {
		u, err := url.Parse(strings.TrimSpace(vaultAddr))
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return nil, fmt.Errorf("secret verifier: vault address must be an https URL without userinfo")
		}
		u.RawQuery, u.Fragment = "", ""
		u.Path = strings.TrimRight(u.Path, "/") + "/v1/auth/token/lookup-self"
		vaultEndpoint = u.String()
	}
	return &Verifier{
		resolver:           resolver,
		public:             safehttp.New(publicHTTPTimeout, false),
		vault:              safehttp.New(publicHTTPTimeout, true),
		github:             githubUserEndpoint,
		githubInstallation: githubInstallationEndpoint,
		sts:                awsSTSEndpoint,
		vaultURL:           vaultEndpoint,
		max:                defaultMaxChecks,
		now:                time.Now,
	}, nil
}

// Verify actively checks supported findings. Unsupported rules are omitted. Provider/network failures are
// represented as unknown results so an outage never turns a leaked-secret presence finding into a clean scan.
func (v *Verifier) Verify(ctx context.Context, root string, findings []ports.SecretRawFinding) ([]ports.SecretVerification, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if v == nil || v.resolver == nil {
		return nil, fmt.Errorf("secret verifier: unavailable")
	}
	ordered := append([]ports.SecretRawFinding(nil), findings...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].File != ordered[j].File {
			return ordered[i].File < ordered[j].File
		}
		if ordered[i].Line != ordered[j].Line {
			return ordered[i].Line < ordered[j].Line
		}
		return ordered[i].RuleID < ordered[j].RuleID
	})

	results := make([]ports.SecretVerification, 0)
	seen := make(map[string]bool)
	checks := 0
	appendResult := func(hit ports.SecretRawFinding, status ports.SecretVerificationStatus, provider, reason string) {
		key := verificationKey(hit)
		if seen[key] {
			return
		}
		seen[key] = true
		results = append(results, ports.SecretVerification{File: hit.File, Line: hit.Line, RuleID: hit.RuleID, Status: status, Provider: provider, Reason: reason})
	}

	// Fixed-format GitHub tokens and Vault service tokens are independently verifiable with one request.
	for _, hit := range ordered {
		provider := ""
		switch hit.RuleID {
		case "github-token", "github-fine-grained-pat":
			provider = providerGitHub
		case "vault-token":
			provider = providerVault
		default:
			continue
		}
		if checks >= v.max {
			appendResult(hit, ports.SecretVerificationUnknown, provider, reasonBudget)
			continue
		}
		if provider == providerVault && v.vaultURL == "" {
			appendResult(hit, ports.SecretVerificationUnknown, provider, reasonUnavailable)
			continue
		}
		raw, found, err := v.materialize(ctx, root, hit)
		if err != nil {
			if ctx.Err() != nil {
				return results, ctx.Err()
			}
			appendResult(hit, ports.SecretVerificationUnknown, provider, reasonMaterial)
			continue
		}
		if !found {
			appendResult(hit, ports.SecretVerificationUnknown, provider, reasonMaterial)
			continue
		}
		checks++
		var status ports.SecretVerificationStatus
		var reason string
		if provider == providerGitHub {
			status, reason = v.verifyGitHub(ctx, raw)
		} else {
			status, reason = v.verifyVault(ctx, raw)
		}
		appendResult(hit, status, provider, reason)
	}

	// AWS STS requires an access-key id AND secret access key (plus a session token for ASIA credentials),
	// so correlate scanner hits before making one GetCallerIdentity request per credential pair.
	awsResults, _, err := v.verifyAWSFindings(ctx, root, ordered, v.max-checks)
	if err != nil {
		return results, err
	}
	for _, result := range awsResults {
		hit := ports.SecretRawFinding{File: result.File, Line: result.Line, RuleID: result.RuleID}
		if !seen[verificationKey(hit)] {
			seen[verificationKey(hit)] = true
			results = append(results, result)
		}
	}
	return results, nil
}

func verificationKey(hit ports.SecretRawFinding) string {
	return hit.RuleID + "\x00" + hit.File + "\x00" + fmt.Sprintf("%d", hit.Line)
}

func (v *Verifier) materialize(ctx context.Context, root string, hit ports.SecretRawFinding) (raw string, found bool, err error) {
	found, err = v.resolver.VisitRawSecret(ctx, root, hit, func(secret string) error {
		raw = secret
		return nil
	})
	return raw, found, err
}

func (v *Verifier) verifyGitHub(ctx context.Context, token string) (ports.SecretVerificationStatus, string) {
	// A GitHub App refresh token (ghr_) can only be exchanged through the app OAuth
	// flow, which requires client credentials. Do not send it to an unrelated endpoint.
	if strings.HasPrefix(token, "ghr_") {
		return ports.SecretVerificationUnknown, reasonUnsupported
	}
	endpoint := v.github
	// Installation tokens (ghs_) identify an installation, not a user; /user rejects
	// them even when live. This read-only endpoint is available to installation tokens.
	if strings.HasPrefix(token, "ghs_") {
		endpoint = v.githubInstallation
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ports.SecretVerificationUnknown, reasonUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := v.public.Do(req)
	if err != nil {
		return ports.SecretVerificationUnknown, reasonUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return ports.SecretVerificationVerified, reasonVerified
	case resp.StatusCode == http.StatusUnauthorized:
		return ports.SecretVerificationUnverified, reasonRejected
	case resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0"):
		return ports.SecretVerificationUnknown, reasonRateLimited
	default:
		return ports.SecretVerificationUnknown, reasonUnavailable
	}
}

func (v *Verifier) verifyVault(ctx context.Context, token string) (ports.SecretVerificationStatus, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.vaultURL, nil)
	if err != nil {
		return ports.SecretVerificationUnknown, reasonUnavailable
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := v.vault.Do(req)
	if err != nil {
		return ports.SecretVerificationUnknown, reasonUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return ports.SecretVerificationVerified, reasonVerified
	case resp.StatusCode == http.StatusForbidden:
		return ports.SecretVerificationUnverified, reasonRejected
	case resp.StatusCode == http.StatusTooManyRequests:
		return ports.SecretVerificationUnknown, reasonRateLimited
	default:
		return ports.SecretVerificationUnknown, reasonUnavailable
	}
}
