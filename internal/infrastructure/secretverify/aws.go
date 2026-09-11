package secretverify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const awsPairLineWindow = 24

func (v *Verifier) verifyAWSFindings(ctx context.Context, root string, findings []ports.SecretRawFinding, budget int) ([]ports.SecretVerification, int, error) {
	byFile := make(map[string][]ports.SecretRawFinding)
	for _, hit := range findings {
		switch hit.RuleID {
		case "aws-access-key-id", "aws-secret-access-key", "aws-session-token":
			byFile[hit.File] = append(byFile[hit.File], hit)
		}
	}
	files := make([]string, 0, len(byFile))
	for file := range byFile {
		files = append(files, file)
	}
	sort.Strings(files)
	var out []ports.SecretVerification
	checked := 0
	seen := make(map[string]bool)
	appendResult := func(hit ports.SecretRawFinding, status ports.SecretVerificationStatus, reason string) {
		key := verificationKey(hit)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, ports.SecretVerification{File: hit.File, Line: hit.Line, RuleID: hit.RuleID, Status: status, Provider: providerAWS, Reason: reason})
	}

	for _, file := range files {
		hits := byFile[file]
		sort.SliceStable(hits, func(i, j int) bool {
			if hits[i].Line != hits[j].Line {
				return hits[i].Line < hits[j].Line
			}
			return hits[i].RuleID < hits[j].RuleID
		})
		for _, accessHit := range hits {
			if accessHit.RuleID != "aws-access-key-id" || seen[verificationKey(accessHit)] {
				continue
			}
			secretHit, ok := uniqueAWSHit(hits, accessHit.Line, "aws-secret-access-key")
			if !ok {
				appendResult(accessHit, ports.SecretVerificationUnknown, reasonMissingPair)
				continue
			}
			if budget <= checked {
				appendResult(accessHit, ports.SecretVerificationUnknown, reasonBudget)
				appendResult(secretHit, ports.SecretVerificationUnknown, reasonBudget)
				continue
			}

			accessRaw, accessFound, err := v.materialize(ctx, root, accessHit)
			if err != nil && ctx.Err() != nil {
				return out, checked, ctx.Err()
			}
			secretRaw, secretFound, err := v.materialize(ctx, root, secretHit)
			if err != nil && ctx.Err() != nil {
				return out, checked, ctx.Err()
			}
			if !accessFound || !secretFound {
				appendResult(accessHit, ports.SecretVerificationUnknown, reasonMaterial)
				appendResult(secretHit, ports.SecretVerificationUnknown, reasonMaterial)
				continue
			}

			var sessionHit ports.SecretRawFinding
			sessionRaw := ""
			if candidate, exists := uniqueAWSHit(hits, accessHit.Line, "aws-session-token"); exists {
				raw, found, rerr := v.materialize(ctx, root, candidate)
				if rerr != nil && ctx.Err() != nil {
					return out, checked, ctx.Err()
				}
				if found {
					sessionHit, sessionRaw = candidate, raw
				}
			}
			if strings.HasPrefix(accessRaw, "ASIA") && sessionRaw == "" {
				appendResult(accessHit, ports.SecretVerificationUnknown, reasonMissingPair)
				appendResult(secretHit, ports.SecretVerificationUnknown, reasonMissingPair)
				continue
			}

			checked++
			status, reason := v.verifyAWS(ctx, accessRaw, secretRaw, sessionRaw)
			appendResult(accessHit, status, reason)
			appendResult(secretHit, status, reason)
			if sessionHit.RuleID != "" {
				appendResult(sessionHit, status, reason)
			}
		}
		// A secret/session-token finding without one unambiguous nearby access-key id cannot authenticate
		// to STS. Preserve the presence finding and make the active result explicitly unknown rather than
		// guessing a pair; a false pairing could otherwise downgrade a live credential to "unverified".
		for _, hit := range hits {
			if (hit.RuleID == "aws-secret-access-key" || hit.RuleID == "aws-session-token") && !seen[verificationKey(hit)] {
				appendResult(hit, ports.SecretVerificationUnknown, reasonMissingPair)
			}
		}
	}
	return out, checked, nil
}

// uniqueAWSHit returns a candidate only when exactly one hit of ruleID falls inside the bounded pairing
// window. Multiple plausible credentials are deliberately ambiguous: active verification must never guess
// which secret belongs to an access key, because a mismatched pair can produce a false "unverified" result.
func uniqueAWSHit(hits []ports.SecretRawFinding, line int, ruleID string) (ports.SecretRawFinding, bool) {
	var candidate ports.SecretRawFinding
	count := 0
	for _, hit := range hits {
		if hit.RuleID != ruleID {
			continue
		}
		d := hit.Line - line
		if d < 0 {
			d = -d
		}
		if d <= awsPairLineWindow {
			candidate = hit
			count++
		}
	}
	return candidate, count == 1
}

func (v *Verifier) verifyAWS(ctx context.Context, accessKey, secretKey, sessionToken string) (ports.SecretVerificationStatus, string) {
	body := "Action=GetCallerIdentity&Version=2011-06-15"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.sts, strings.NewReader(body))
	if err != nil {
		return ports.SecretVerificationUnknown, reasonUnavailable
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	now := v.now().UTC()
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	if sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", sessionToken)
	}
	signedHeaders, canonicalHeaders := awsCanonicalHeaders(req, sessionToken != "")
	payloadHash := sha256Hex([]byte(body))
	uri := req.URL.EscapedPath()
	if uri == "" {
		uri = "/"
	}
	canonicalRequest := strings.Join([]string{
		http.MethodPost,
		uri,
		canonicalQuery(req.URL),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")
	scope := date + "/us-east-1/sts/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonicalRequest))
	signingKey := awsSigningKey(secretKey, date, "us-east-1", "sts")
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+accessKey+"/"+scope+", SignedHeaders="+signedHeaders+", Signature="+signature)

	resp, err := v.public.Do(req)
	if err != nil {
		return ports.SecretVerificationUnknown, reasonUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return ports.SecretVerificationVerified, reasonVerified
	}
	lower := strings.ToLower(string(data))
	for _, code := range []string{"invalidclienttokenid", "signaturedoesnotmatch", "expiredtoken", "tokenrefreshrequired", "unrecognizedclientexception"} {
		if strings.Contains(lower, code) {
			return ports.SecretVerificationUnverified, reasonRejected
		}
	}
	if resp.StatusCode == http.StatusTooManyRequests || strings.Contains(lower, "throttl") || strings.Contains(lower, "requestlimitexceeded") {
		return ports.SecretVerificationUnknown, reasonRateLimited
	}
	return ports.SecretVerificationUnknown, reasonUnavailable
}

func awsCanonicalHeaders(req *http.Request, withToken bool) (signed, canonical string) {
	headers := []string{"content-type", "host", "x-amz-date"}
	if withToken {
		headers = append(headers, "x-amz-security-token")
	}
	signed = strings.Join(headers, ";")
	var b strings.Builder
	b.WriteString("content-type:")
	b.WriteString(strings.TrimSpace(req.Header.Get("Content-Type")))
	b.WriteByte('\n')
	b.WriteString("host:")
	b.WriteString(strings.ToLower(req.URL.Host))
	b.WriteByte('\n')
	b.WriteString("x-amz-date:")
	b.WriteString(req.Header.Get("X-Amz-Date"))
	b.WriteByte('\n')
	if withToken {
		b.WriteString("x-amz-security-token:")
		b.WriteString(strings.TrimSpace(req.Header.Get("X-Amz-Security-Token")))
		b.WriteByte('\n')
	}
	return signed, b.String()
}

func canonicalQuery(u *url.URL) string {
	if u == nil || u.RawQuery == "" {
		return ""
	}
	return u.Query().Encode()
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func awsSigningKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}
