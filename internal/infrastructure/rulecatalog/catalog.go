package rulecatalog

import (
	"context"
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type Catalog struct {
	byKey map[rule.Key]rule.Rule
	keys  []rule.Key
}

func New(entries []rule.Rule) (*Catalog, error) {
	byKey := make(map[rule.Key]rule.Rule, len(entries))
	var keys []rule.Key

	for _, e := range entries {
		if err := e.Validate(); err != nil {
			return nil, fmt.Errorf("validate rule %q: %w", e.Key, err)
		}
		if _, exists := byKey[e.Key]; exists {
			return nil, fmt.Errorf("duplicate rule key %q", e.Key)
		}
		c := e.Clone()
		byKey[c.Key] = c
		keys = append(keys, c.Key)
	}

	sort.SliceStable(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})

	return &Catalog{
		byKey: byKey,
		keys:  keys,
	}, nil
}

func (c *Catalog) List(ctx context.Context) ([]rule.Rule, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if len(c.keys) == 0 {
		return []rule.Rule{}, nil
	}

	res := make([]rule.Rule, 0, len(c.keys))
	for _, k := range c.keys {
		res = append(res, c.byKey[k].Clone())
	}
	return res, nil
}

func (c *Catalog) Get(ctx context.Context, key rule.Key) (rule.Rule, error) {
	if ctx.Err() != nil {
		return rule.Rule{}, ctx.Err()
	}

	r, ok := c.byKey[key]
	if !ok {
		return rule.Rule{}, shared.ErrNotFound
	}
	return r.Clone(), nil
}
