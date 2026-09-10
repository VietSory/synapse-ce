package ast

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.JSFactsProvider = (*Provider)(nil)

// JSFacts runs `synapse-ast js-facts <root>`. The sidecar parses attacker-controlled JS/TS/TSX,
// so its versioned wire document is validated again at the application trust boundary before use.
func (p *Provider) JSFacts(ctx context.Context, root string) (jsprogram.Document, bool, error) {
	if strings.TrimSpace(root) == "" {
		return jsprogram.Document{}, false, nil
	}
	out, exit, err := p.run(ctx, "js-facts", root)
	if exit == exitUnavailable {
		return jsprogram.Document{}, false, nil
	}
	if err != nil {
		return jsprogram.Document{}, false, err
	}
	var document jsprogram.Document
	if err := json.Unmarshal(out, &document); err != nil {
		return jsprogram.Document{}, false, fmt.Errorf("parse synapse-ast javascript facts: %w", err)
	}
	if err := document.Validate(); err != nil {
		return jsprogram.Document{}, false, fmt.Errorf("validate synapse-ast javascript facts: %w", err)
	}
	return document, true, nil
}
