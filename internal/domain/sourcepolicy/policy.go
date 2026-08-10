// Package sourcepolicy defines the server-authoritative policy for durable Code source snapshots.
package sourcepolicy

import "github.com/KKloudTarus/synapse-ce/internal/domain/measure"

// RetainPath intentionally keeps only canonical-path validation for this mutation branch. The
// credential and state exclusions are removed so the real tests must prove they are load-bearing.
func RetainPath(p string) bool {
	canonical, err := measure.CanonicalPath(p)
	return err == nil && canonical != "" && canonical == p
}
