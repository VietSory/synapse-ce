package sourceartifact

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// validateWriteRoot fails closed before any source artifact write. In particular, a caller may not
// rely on the process working directory to turn an untrusted relative path into durable evidence.
func (s *Store) validateWriteRoot() error {
	if !filepath.IsAbs(s.root) {
		return fmt.Errorf("%w: source artifact root must be absolute", shared.ErrValidation)
	}
	if err := os.MkdirAll(s.root, 0o700); err != nil {
		return fmt.Errorf("create source artifact root: %w", err)
	}
	info, err := os.Lstat(s.root)
	if err != nil {
		return fmt.Errorf("inspect source artifact root: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: source artifact root must be an operator-owned directory, not a symlink", shared.ErrValidation)
	}
	return nil
}
