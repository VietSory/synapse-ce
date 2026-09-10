package rulecatalog

import "testing"

func TestJavaScriptTaintCatalogRulesHaveCompleteFirstPartyMetadata(t *testing.T) {
	rules := javascriptTaintRules()
	if len(rules) != 10 {
		t.Fatalf("javascript taint rules = %d, want 10", len(rules))
	}
	seen := map[string]bool{}
	for _, item := range rules {
		if err := item.Validate(); err != nil {
			t.Fatalf("rule %s: %v", item.Key, err)
		}
		key := string(item.Key)
		if seen[key] {
			t.Fatalf("duplicate javascript taint rule %q", key)
		}
		seen[key] = true
		if item.Language != "JavaScript/TypeScript" || len(item.CWE) != 1 || len(item.OWASP) != 1 || item.Description == "" || item.Rationale == "" || item.Remediation == "" {
			t.Fatalf("incomplete metadata for %s: %+v", item.Key, item)
		}
	}
	for _, key := range []string{
		"javascript-taint-command", "javascript-taint-eval", "javascript-taint-sqli", "javascript-taint-nosql",
		"javascript-taint-path", "javascript-taint-ssrf", "javascript-taint-xss", "javascript-taint-open-redirect",
		"javascript-taint-ssti", "javascript-taint-deserialization",
	} {
		if !seen[key] {
			t.Errorf("missing catalog rule %q", key)
		}
	}
}
