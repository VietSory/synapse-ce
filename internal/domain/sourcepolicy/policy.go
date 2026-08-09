// Package sourcepolicy defines the server-authoritative policy for durable Code source snapshots.
package sourcepolicy

import (
	"path"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
)

// RetainPath reports whether a canonical, scanner-owned source path is safe to retain durably.
// The analysis snapshot remains the primary allowlist; this denylist is defense-in-depth for
// credential-shaped files that must never become source artifacts even if a scanner inventory drifts.
func RetainPath(p string) bool {
	canonical, err := measure.CanonicalPath(p)
	if err != nil || canonical == "" || canonical != p {
		return false
	}
	name := strings.ToLower(path.Base(canonical))
	if name == ".env" || strings.HasPrefix(name, ".env.") {
		return false
	}
	switch name {
	case ".netrc", ".npmrc", ".pypirc", ".git-credentials", "credentials.json",
		"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519":
		return false
	}
	switch strings.ToLower(path.Ext(name)) {
	case ".pem", ".key", ".p12", ".pfx", ".jks":
		return false
	}
	return true
}
