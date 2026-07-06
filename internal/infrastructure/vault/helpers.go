package vault

import (
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// maxNameLen bounds a credential name (it is also the placeholder token).
const maxNameLen = 128

// validateName enforces a safe, bounded credential name: it is embedded in the
// {{secret:NAME}} placeholder and may seed an environment-variable key, so only
// [A-Za-z0-9_.-] is allowed (no spaces, no shell/argv metacharacters).
func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: credential name is required", shared.ErrValidation)
	}
	if len(name) > maxNameLen {
		return fmt.Errorf("%w: credential name too long (max %d)", shared.ErrValidation, maxNameLen)
	}
	for _, r := range name {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.'
		if !ok {
			return fmt.Errorf("%w: credential name may only contain [A-Za-z0-9_.-]", shared.ErrValidation)
		}
	}
	return nil
}

func sortMetaByName(m []ports.CredentialMeta) {
	sort.Slice(m, func(i, j int) bool { return m[i].Name < m[j].Name })
}
