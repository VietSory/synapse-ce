package jsresolve

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
	"path/filepath"
)

func graphWithExternal(from, specifier string) modulegraph.Graph {
	return modulegraph.Graph{
		Modules: []modulegraph.Module{{Path: from, Dialect: modulegraph.DialectTypeScript}},
		Edges:   []modulegraph.Edge{{From: from, Specifier: specifier, Kind: modulegraph.ImportESMStatic}},
	}
}

func resolutionsBySpecifier(values []jsresolution.ImportResolution) map[string]jsresolution.ImportResolution {
	out := make(map[string]jsresolution.ImportResolution, len(values))
	for _, value := range values {
		out[value.Specifier] = value
	}
	return out
}

func r2bJoin(parts ...string) string {
	return filepath.Join(parts...)
}
