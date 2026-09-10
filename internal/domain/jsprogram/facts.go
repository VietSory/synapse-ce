// Package jsprogram defines the deterministic, source-only semantic facts used by
// JavaScript/TypeScript value-flow taint analysis. The model is parser-independent:
// tree-sitter stays behind the AST sidecar and callers validate every document at
// this trust boundary before analysis.
package jsprogram

import (
	"fmt"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	SchemaVersion = 1

	maxFiles       = 200_000
	maxSymbols     = 2_000_000
	maxFacts       = 4_000_000
	maxParameters  = 1_024
	maxArguments   = 4_096
	maxSegments    = 256
	maxStringBytes = 4_096
)

type SymbolKind string

const (
	SymbolModule   SymbolKind = "module"
	SymbolFunction SymbolKind = "function"
	SymbolMethod   SymbolKind = "method"
	SymbolClass    SymbolKind = "class"
	SymbolArrow    SymbolKind = "arrow"
)

func (k SymbolKind) Valid() bool {
	switch k {
	case SymbolModule, SymbolFunction, SymbolMethod, SymbolClass, SymbolArrow:
		return true
	}
	return false
}

type ReferenceKind string

const (
	ReferenceName       ReferenceKind = "name"
	ReferenceMember     ReferenceKind = "member"
	ReferenceCall       ReferenceKind = "call"
	ReferenceExpression ReferenceKind = "expression"
	ReferenceLiteral    ReferenceKind = "literal"
	ReferenceUnknown    ReferenceKind = "unknown"
)

func (k ReferenceKind) Valid() bool {
	switch k {
	case ReferenceName, ReferenceMember, ReferenceCall, ReferenceExpression, ReferenceLiteral, ReferenceUnknown:
		return true
	}
	return false
}

type GapKind string

const (
	GapParseRecovery    GapKind = "parse_recovery"
	GapDynamicImport    GapKind = "dynamic_import"
	GapDynamicExecution GapKind = "dynamic_execution"
	GapDynamicProperty  GapKind = "dynamic_property"
	GapUnresolvedCall   GapKind = "unresolved_call"
	GapUnresolvedValue  GapKind = "unresolved_value"
	GapModuleResolution GapKind = "module_resolution"
	GapBudget           GapKind = "budget"
	GapUnreadable       GapKind = "unreadable"
)

func (k GapKind) Valid() bool {
	switch k {
	case GapParseRecovery, GapDynamicImport, GapDynamicExecution, GapDynamicProperty,
		GapUnresolvedCall, GapUnresolvedValue, GapModuleResolution, GapBudget, GapUnreadable:
		return true
	}
	return false
}

type Position struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

type Reference struct {
	Kind     ReferenceKind `json:"kind"`
	Segments []string      `json:"segments,omitempty"`
}

type Parameter struct {
	Name    string   `json:"name"`
	ValueID string   `json:"value_id,omitempty"`
	Pos     Position `json:"position"`
	Rest    bool     `json:"rest,omitempty"`
}

type Module struct {
	Name string   `json:"name"`
	File string   `json:"file"`
	Pos  Position `json:"position"`
}

type Symbol struct {
	ID            string      `json:"id"`
	Module        string      `json:"module"`
	QualifiedName string      `json:"qualified_name"`
	Name          string      `json:"name"`
	ParentID      string      `json:"parent_id,omitempty"`
	Kind          SymbolKind  `json:"kind"`
	Pos           Position    `json:"position"`
	Parameters    []Parameter `json:"parameters,omitempty"`
	Async         bool        `json:"async,omitempty"`
}

// Import records ESM imports and statically-resolved CommonJS require bindings.
type Import struct {
	ScopeID string   `json:"scope_id"`
	Module  string   `json:"module"`
	Name    string   `json:"name,omitempty"`
	Alias   string   `json:"alias,omitempty"`
	Default bool     `json:"default,omitempty"`
	Star    bool     `json:"star,omitempty"`
	Pos     Position `json:"position"`
}

type Argument struct {
	Name    string    `json:"name,omitempty"`
	Spread  bool      `json:"spread,omitempty"`
	Value   Reference `json:"value"`
	ValueID string    `json:"value_id,omitempty"`
	Pos     Position  `json:"position"`
}

type Call struct {
	ID              string      `json:"id"`
	CallerID        string      `json:"caller_id"`
	Callee          Reference   `json:"callee"`
	Arguments       []Argument  `json:"arguments,omitempty"`
	ResultID        string      `json:"result_id,omitempty"`
	ReceiverValueID string      `json:"receiver_value_id,omitempty"`
	Pos             Position    `json:"position"`
	Optional        bool        `json:"optional,omitempty"`
	Constructor     bool        `json:"constructor,omitempty"`
}

type Assignment struct {
	ScopeID   string      `json:"scope_id"`
	Targets   []Reference `json:"targets"`
	TargetIDs []string    `json:"target_ids,omitempty"`
	Value     Reference   `json:"value"`
	ValueID   string      `json:"value_id,omitempty"`
	Pos       Position    `json:"position"`
}

type Return struct {
	ScopeID string    `json:"scope_id"`
	Value   Reference `json:"value"`
	ValueID string    `json:"value_id,omitempty"`
	SlotID  string    `json:"slot_id,omitempty"`
	Pos     Position  `json:"position"`
}

type ValueKind string

const (
	ValueParameter  ValueKind = "parameter"
	ValueBinding    ValueKind = "binding"
	ValueReference  ValueKind = "reference"
	ValueCallResult ValueKind = "call_result"
	ValueExpression ValueKind = "expression"
	ValueLiteral    ValueKind = "literal"
	ValueReturn     ValueKind = "return"
	ValueProperty   ValueKind = "property"
)

func (k ValueKind) Valid() bool {
	switch k {
	case ValueParameter, ValueBinding, ValueReference, ValueCallResult,
		ValueExpression, ValueLiteral, ValueReturn, ValueProperty:
		return true
	}
	return false
}

type Value struct {
	ID      string    `json:"id"`
	ScopeID string    `json:"scope_id"`
	Kind    ValueKind `json:"kind"`
	Name    string    `json:"name,omitempty"`
	Ref     Reference `json:"reference"`
	Pos     Position  `json:"position"`
}

type ValueFlowKind string

const (
	FlowExpression ValueFlowKind = "expression"
	FlowMember     ValueFlowKind = "member"
	FlowAssignment ValueFlowKind = "assignment"
	FlowReturn     ValueFlowKind = "return"
	FlowArgument   ValueFlowKind = "argument"
)

func (k ValueFlowKind) Valid() bool {
	switch k {
	case FlowExpression, FlowMember, FlowAssignment, FlowReturn, FlowArgument:
		return true
	}
	return false
}

type ValueFlow struct {
	FromID string        `json:"from_id"`
	ToID   string        `json:"to_id"`
	Kind   ValueFlowKind `json:"kind"`
	Pos    Position      `json:"position"`
}

type CoverageGap struct {
	Kind     GapKind  `json:"kind"`
	SymbolID string   `json:"symbol_id,omitempty"`
	Detail   string   `json:"detail,omitempty"`
	Pos      Position `json:"position"`
}

type Document struct {
	SchemaVersion int           `json:"schema_version"`
	Modules       []Module      `json:"modules"`
	Symbols       []Symbol      `json:"symbols"`
	Imports       []Import      `json:"imports"`
	Calls         []Call        `json:"calls"`
	Assignments   []Assignment  `json:"assignments"`
	Returns       []Return      `json:"returns"`
	Values        []Value       `json:"values"`
	Flows         []ValueFlow   `json:"flows"`
	CoverageGaps  []CoverageGap `json:"coverage_gaps"`
	FilesSeen     int           `json:"files_seen"`
	FilesParsed   int           `json:"files_parsed"`
	NodesSeen     int           `json:"nodes_seen"`
	Truncated     bool          `json:"truncated"`
}

func (d Document) Complete() bool {
	return !d.Truncated && len(d.CoverageGaps) == 0 && d.FilesSeen > 0 && d.FilesSeen == d.FilesParsed
}

// Validate rejects malformed, dangling, duplicate, or unbounded sidecar output before analysis.
// Dynamic expression/call references may intentionally have no stable segment list; the matching
// coverage gap is what prevents them from being used as negative proof.
func (d Document) Validate() error {
	if d.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: unsupported javascript facts schema version %d", shared.ErrValidation, d.SchemaVersion)
	}
	if d.FilesSeen < 0 || d.FilesParsed < 0 || d.FilesParsed > d.FilesSeen || d.FilesSeen > maxFiles || d.NodesSeen < 0 {
		return fmt.Errorf("%w: invalid javascript facts coverage counters", shared.ErrValidation)
	}
	if len(d.Modules) > maxFiles || len(d.Symbols) > maxSymbols || len(d.Imports) > maxFacts ||
		len(d.Calls) > maxFacts || len(d.Assignments) > maxFacts || len(d.Returns) > maxFacts ||
		len(d.Values) > maxFacts || len(d.Flows) > maxFacts || len(d.CoverageGaps) > maxFacts {
		return fmt.Errorf("%w: javascript facts document exceeds bounds", shared.ErrValidation)
	}

	modules := make(map[string]string, len(d.Modules))
	files := make(map[string]bool, len(d.Modules))
	for _, item := range d.Modules {
		if !validToken(item.Name) || validatePosition(item.Pos) != nil || item.File != item.Pos.File || files[item.File] {
			return fmt.Errorf("%w: invalid javascript module fact", shared.ErrValidation)
		}
		if _, duplicate := modules[item.Name]; duplicate {
			return fmt.Errorf("%w: duplicate javascript module", shared.ErrValidation)
		}
		modules[item.Name], files[item.File] = item.File, true
	}

	symbols := make(map[string]Symbol, len(d.Symbols))
	moduleRoots := make(map[string]int, len(d.Modules))
	parameterValueIDs := make([]string, 0)
	for _, item := range d.Symbols {
		if !validToken(item.ID) || !item.Kind.Valid() || !validToken(item.Module) || !validToken(item.QualifiedName) ||
			!validToken(item.Name) || len(item.Parameters) > maxParameters || validatePosition(item.Pos) != nil || modules[item.Module] != item.Pos.File {
			return fmt.Errorf("%w: invalid javascript symbol fact", shared.ErrValidation)
		}
		if _, duplicate := symbols[item.ID]; duplicate {
			return fmt.Errorf("%w: duplicate javascript symbol", shared.ErrValidation)
		}
		if item.Kind == SymbolModule {
			moduleRoots[item.Module]++
		}
		for _, parameter := range item.Parameters {
			if !validToken(parameter.Name) || validatePosition(parameter.Pos) != nil || parameter.Pos.File != item.Pos.File ||
				(parameter.ValueID != "" && !validToken(parameter.ValueID)) {
				return fmt.Errorf("%w: invalid javascript parameter fact", shared.ErrValidation)
			}
			if parameter.ValueID != "" {
				parameterValueIDs = append(parameterValueIDs, parameter.ValueID)
			}
		}
		symbols[item.ID] = item
	}
	for module := range modules {
		if moduleRoots[module] != 1 {
			return fmt.Errorf("%w: javascript module needs exactly one module symbol", shared.ErrValidation)
		}
	}
	for _, item := range d.Symbols {
		if item.Kind == SymbolModule {
			if item.ParentID != "" {
				return fmt.Errorf("%w: javascript module symbol cannot have a parent", shared.ErrValidation)
			}
			continue
		}
		if item.ParentID == "" {
			return fmt.Errorf("%w: javascript non-module symbol needs a parent", shared.ErrValidation)
		}
		parent, ok := symbols[item.ParentID]
		if !ok || parent.Module != item.Module {
			return fmt.Errorf("%w: javascript symbol parent does not exist in its module", shared.ErrValidation)
		}
	}

	values := make(map[string]Value, len(d.Values))
	for _, item := range d.Values {
		if !validToken(item.ID) || !item.Kind.Valid() || !validToken(item.ScopeID) || validatePosition(item.Pos) != nil {
			return fmt.Errorf("%w: invalid javascript value fact", shared.ErrValidation)
		}
		if item.Name != "" && !validToken(item.Name) {
			return fmt.Errorf("%w: invalid javascript value name", shared.ErrValidation)
		}
		owner, ok := symbols[item.ScopeID]
		if !ok || owner.Pos.File != item.Pos.File {
			return fmt.Errorf("%w: invalid javascript value owner", shared.ErrValidation)
		}
		if _, duplicate := values[item.ID]; duplicate {
			return fmt.Errorf("%w: duplicate javascript value", shared.ErrValidation)
		}
		if err := validateReference(item.Ref); err != nil {
			return err
		}
		values[item.ID] = item
	}
	for _, id := range parameterValueIDs {
		value, ok := values[id]
		if !ok || value.Kind != ValueParameter {
			return fmt.Errorf("%w: javascript parameter references a missing/non-parameter value", shared.ErrValidation)
		}
	}

	for _, item := range d.Imports {
		if _, ok := symbols[item.ScopeID]; !ok || !validToken(item.Module) || validatePosition(item.Pos) != nil || item.Default && item.Star {
			return fmt.Errorf("%w: invalid javascript import fact", shared.ErrValidation)
		}
		if item.Name != "" && !validToken(item.Name) || item.Alias != "" && !validToken(item.Alias) {
			return fmt.Errorf("%w: invalid javascript import binding", shared.ErrValidation)
		}
	}

	callIDs := make(map[string]bool, len(d.Calls))
	for _, item := range d.Calls {
		caller, ok := symbols[item.CallerID]
		if !validToken(item.ID) || !ok || callIDs[item.ID] || len(item.Arguments) > maxArguments || validatePosition(item.Pos) != nil || caller.Pos.File != item.Pos.File {
			return fmt.Errorf("%w: invalid or duplicate javascript call fact", shared.ErrValidation)
		}
		callIDs[item.ID] = true
		if err := validateReference(item.Callee); err != nil {
			return err
		}
		for _, argument := range item.Arguments {
			if validatePosition(argument.Pos) != nil || argument.Pos.File != item.Pos.File || (argument.Name != "" && !validToken(argument.Name)) {
				return fmt.Errorf("%w: invalid javascript call argument", shared.ErrValidation)
			}
			if argument.ValueID != "" {
				if _, ok := values[argument.ValueID]; !ok {
					return fmt.Errorf("%w: javascript call argument value does not exist", shared.ErrValidation)
				}
			}
			if err := validateReference(argument.Value); err != nil {
				return err
			}
		}
		if item.ResultID != "" {
			if _, ok := values[item.ResultID]; !ok {
				return fmt.Errorf("%w: javascript call result value does not exist", shared.ErrValidation)
			}
		}
		if item.ReceiverValueID != "" {
			if _, ok := values[item.ReceiverValueID]; !ok {
				return fmt.Errorf("%w: javascript call receiver value does not exist", shared.ErrValidation)
			}
		}
	}

	for _, item := range d.Assignments {
		if _, ok := symbols[item.ScopeID]; !ok || len(item.Targets) == 0 || len(item.Targets) > maxArguments || validatePosition(item.Pos) != nil {
			return fmt.Errorf("%w: invalid javascript assignment fact", shared.ErrValidation)
		}
		if len(item.TargetIDs) != 0 && len(item.TargetIDs) != len(item.Targets) {
			return fmt.Errorf("%w: javascript assignment target id cardinality mismatch", shared.ErrValidation)
		}
		for index, target := range item.Targets {
			if err := validateReference(target); err != nil {
				return err
			}
			if len(item.TargetIDs) > index {
				if _, ok := values[item.TargetIDs[index]]; !ok {
					return fmt.Errorf("%w: javascript assignment target value does not exist", shared.ErrValidation)
				}
			}
		}
		if item.Value.Kind.Valid() {
			if err := validateReference(item.Value); err != nil {
				return err
			}
		} else if item.ValueID == "" {
			return fmt.Errorf("%w: javascript assignment has no value", shared.ErrValidation)
		}
		if item.ValueID != "" {
			if _, ok := values[item.ValueID]; !ok {
				return fmt.Errorf("%w: javascript assignment source value does not exist", shared.ErrValidation)
			}
		}
	}

	for _, item := range d.Returns {
		owner, ok := symbols[item.ScopeID]
		if !ok || owner.Kind == SymbolModule || owner.Kind == SymbolClass || validatePosition(item.Pos) != nil {
			return fmt.Errorf("%w: invalid javascript return fact", shared.ErrValidation)
		}
		if err := validateReference(item.Value); err != nil {
			return err
		}
		if item.ValueID == "" || item.SlotID == "" {
			return fmt.Errorf("%w: javascript return needs source and slot values", shared.ErrValidation)
		}
		value, valueOK := values[item.ValueID]
		slot, slotOK := values[item.SlotID]
		if !valueOK || !slotOK || slot.Kind != ValueReturn || value.Pos.File != owner.Pos.File || slot.Pos.File != owner.Pos.File {
			return fmt.Errorf("%w: javascript return references invalid values", shared.ErrValidation)
		}
	}

	for _, item := range d.Flows {
		from, fromOK := values[item.FromID]
		to, toOK := values[item.ToID]
		if !item.Kind.Valid() || !fromOK || !toOK || validatePosition(item.Pos) != nil || from.Pos.File != item.Pos.File || to.Pos.File != item.Pos.File {
			return fmt.Errorf("%w: invalid javascript value-flow fact", shared.ErrValidation)
		}
	}
	for _, gap := range d.CoverageGaps {
		if !gap.Kind.Valid() || validatePosition(gap.Pos) != nil || len(gap.Detail) > maxStringBytes || !utf8.ValidString(gap.Detail) {
			return fmt.Errorf("%w: invalid javascript coverage gap", shared.ErrValidation)
		}
		if gap.SymbolID != "" {
			if _, ok := symbols[gap.SymbolID]; !ok {
				return fmt.Errorf("%w: javascript coverage gap references unknown symbol", shared.ErrValidation)
			}
		}
	}
	return nil
}

func validateReference(ref Reference) error {
	if !ref.Kind.Valid() || len(ref.Segments) > maxSegments {
		return fmt.Errorf("%w: invalid javascript reference", shared.ErrValidation)
	}
	// Unknown/expression/call are intentionally allowed to have no stable segment list.
	// The extractor must pair unresolved dynamic shapes with a CoverageGap.
	if (ref.Kind == ReferenceName || ref.Kind == ReferenceMember) && len(ref.Segments) == 0 {
		return fmt.Errorf("%w: javascript reference requires segments", shared.ErrValidation)
	}
	for _, segment := range ref.Segments {
		if !validToken(segment) {
			return fmt.Errorf("%w: invalid javascript reference segment", shared.ErrValidation)
		}
	}
	return nil
}

func validatePosition(pos Position) error {
	if pos.Line <= 0 || pos.Column < 0 || len(pos.File) == 0 || len(pos.File) > maxStringBytes || !utf8.ValidString(pos.File) {
		return fmt.Errorf("%w: invalid javascript position", shared.ErrValidation)
	}
	clean := path.Clean(strings.ReplaceAll(pos.File, "\\", "/"))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") || clean != strings.ReplaceAll(pos.File, "\\", "/") {
		return fmt.Errorf("%w: javascript position must be a normalized relative path", shared.ErrValidation)
	}
	return nil
}

func validToken(value string) bool {
	return value != "" && len(value) <= maxStringBytes && utf8.ValidString(value) && !strings.ContainsRune(value, '\x00')
}
