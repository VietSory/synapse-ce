package secretverify

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Scanner decorates deterministic secret detection with an explicit active-verification lane. Ordinary
// SecretScanner.ScanFiles remains detection-only; the SCA pipeline opts into network activity by type-asserting
// ports.SecretVerificationScanner and calling ScanFilesVerified. This keeps the default scanner contract
// deterministic and makes the egress boundary visible at the composition/use-case seam.
type Scanner struct {
	base     ports.SecretScanner
	verifier ports.SecretVerifier
}

var _ ports.SecretScanner = (*Scanner)(nil)
var _ ports.SecretHistoryScanner = (*Scanner)(nil)
var _ ports.SecretVerificationScanner = (*Scanner)(nil)

func WrapScanner(base ports.SecretScanner, verifier ports.SecretVerifier) (*Scanner, error) {
	if base == nil || verifier == nil {
		return nil, fmt.Errorf("secret verification scanner requires base scanner and verifier")
	}
	return &Scanner{base: base, verifier: verifier}, nil
}

func (s *Scanner) Name() string { return s.base.Name() }

// ScanFiles preserves the deterministic/no-network SecretScanner contract. Active verification is never
// reached through this method, so code paths that do not explicitly know about the extension stay unchanged.
func (s *Scanner) ScanFiles(ctx context.Context, root string) (ports.SecretScanReport, error) {
	return s.base.ScanFiles(ctx, root)
}

// ScanFilesVerified runs the same deterministic presence scan first, then the bounded provider verifier over
// those already-redacted findings. A provider failure is best-effort: presence facts are retained, while a
// cancelled/deadline context still propagates to the caller.
func (s *Scanner) ScanFilesVerified(ctx context.Context, root string) (ports.SecretScanReport, []ports.SecretVerification, error) {
	report, err := s.base.ScanFiles(ctx, root)
	if err != nil || len(report.Findings) == 0 {
		return report, nil, err
	}
	results, verr := s.verifier.Verify(ctx, root, report.Findings)
	if verr != nil {
		if ctx.Err() != nil {
			return report, nil, ctx.Err()
		}
		return report, nil, nil
	}
	valid := results[:0]
	for _, result := range results {
		if result.Valid() {
			valid = append(valid, result)
		}
	}
	return report, valid, nil
}

// ScanHistory preserves the base scanner's git-history capability. Active verification deliberately does not
// reconstruct credentials from historical blobs in this slice: a removed credential is still reported, but only
// current worktree material is ever transmitted to a provider.
func (s *Scanner) ScanHistory(ctx context.Context, root string) (ports.SecretScanReport, error) {
	history, ok := s.base.(ports.SecretHistoryScanner)
	if !ok {
		return ports.SecretScanReport{}, nil
	}
	return history.ScanHistory(ctx, root)
}
