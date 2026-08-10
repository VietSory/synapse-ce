// Package sourcepolicy defines the server-authoritative policy for durable Code source snapshots.
package sourcepolicy

import (
	"path"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
)

var ignoredSegments = map[string]struct{}{
	".git": {}, ".hg": {}, ".svn": {}, ".idea": {}, ".vscode": {}, ".tox": {},
	".venv": {}, "venv": {}, "__pycache__": {}, "node_modules": {}, "vendor": {},
	"dist": {}, "build": {}, "target": {},
}

// RetainPath reports whether a canonical, scanner-owned source path is safe to retain durably.
// The analysis snapshot remains the primary allowlist. This policy mirrors the inventory's heavy
// state/vendor exclusions and adds credential-shaped files that must never become source artifacts,
// even if a producer's inventory drifts.
func RetainPath(p string) bool {
	canonical, err := measure.CanonicalPath(p)
	return err == nil && canonical != "" && canonical == p
}
