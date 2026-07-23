package codeanalysis

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ─── Thresholds (named constants, all exact-boundary tested) ──────────────────

const (
	xmlMaxMaintainableDepth              = 16
	xmlMaxAttributesPerElement           = 12
	xmlMaxDirectChildren                 = 25
	xmlMinDistinctChildNames             = 6
	xmlOversizedElementLineSpan          = 200
	xmlOversizedElementMinDescendants    = 20
	xmlOversizedElementMinDistinctNames  = 5
	xmlMaxCommentBytes                   = 1000
	xmlMaxCommentLines                   = 20
	xmlMaxCommentedMarkupProbeBytes      = 64 * 1024
	xmlDistinctNameTrackingCap           = 64
	xmlMaxMaintainabilityFindingsPerRule = 20
	xmlMaxMaintainabilityFindingsPerFile = 100
)

// xsiInstanceURI is the XML Schema-instance namespace. Resolved by URI, never
// by hard-coded prefix.
const xsiInstanceURI = "http://www.w3.org/2001/XMLSchema-instance"

// truncateXMLDiagnosticValue caps user-controlled strings in diagnostic messages.
func truncateXMLDiagnosticValue(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// ─── Finding collector (cap enforcement) ──────────────────────────────────────

type xmlMaintainabilityCollector struct {
	findings   []ports.CodeAnalysisRawFinding
	perRule    map[string]int
	totalCount int
}

func newXMLMaintainabilityCollector() *xmlMaintainabilityCollector {
	return &xmlMaintainabilityCollector{perRule: make(map[string]int)}
}

func (c *xmlMaintainabilityCollector) add(f ports.CodeAnalysisRawFinding) {
	if c.totalCount >= xmlMaxMaintainabilityFindingsPerFile {
		return
	}
	if c.perRule[f.RuleID] >= xmlMaxMaintainabilityFindingsPerRule {
		return
	}
	c.findings = append(c.findings, f)
	c.perRule[f.RuleID]++
	c.totalCount++
}

// ─── Namespace declaration tracking ───────────────────────────────────────────

type xmlNSDecl struct {
	prefix       string // "" = default namespace
	uri          string
	inheritedURI string // Store inherited URI at time of creation
	line         int
	used         bool
	redundant    bool // repeats an inherited binding
	shadowing    bool // rebinds a named prefix to a different URI
	reserved     bool // xml or xmlns prefixes should not trigger findings
}

// ─── Per-element frame ────────────────────────────────────────────────────────

type xmlMaintFrame struct {
	qname     string
	startLine int
	depth     int

	// Direct child tracking.
	directChildCount    int
	directChildCounts   map[string]int // QName → count
	distinctDirectNames map[string]struct{}
	directSaturated     bool
	homogeneityUnknown  bool

	// Subtree tracking (aggregated on close).
	descendantCount   int
	distinctDescNames map[string]struct{}
	descSaturated     bool

	// Namespace declarations on this element.
	decls []*xmlNSDecl
}

func newXMLMaintFrame(qname string, line, depth int) *xmlMaintFrame {
	return &xmlMaintFrame{
		qname:               qname,
		startLine:           line,
		depth:               depth,
		directChildCounts:   make(map[string]int),
		distinctDirectNames: make(map[string]struct{}),
		distinctDescNames:   make(map[string]struct{}),
	}
}

// addDirectChild records one direct child to the parent frame.
func (f *xmlMaintFrame) addDirectChild(childQName string) {
	f.directChildCount++
	if !f.directSaturated {
		f.distinctDirectNames[childQName] = struct{}{}
		f.directChildCounts[childQName]++
		if len(f.distinctDirectNames) >= xmlDistinctNameTrackingCap {
			f.directSaturated = true
			f.homogeneityUnknown = true
		}
	} else {
		if _, ok := f.distinctDirectNames[childQName]; ok {
			f.directChildCounts[childQName]++
		}
	}
}

// mergeDescendant merges a closed child frame into this parent's descendant counters.
func (f *xmlMaintFrame) mergeDescendant(child *xmlMaintFrame) {
	f.descendantCount += 1 + child.descendantCount
	if !f.descSaturated {
		f.distinctDescNames[child.qname] = struct{}{}
		for n := range child.distinctDescNames {
			f.distinctDescNames[n] = struct{}{}
			if len(f.distinctDescNames) >= xmlDistinctNameTrackingCap {
				f.descSaturated = true
				break
			}
		}
	}
}

// isHomogeneousList returns true when the element's direct children are dominated
// by a single name at >= 80%, preventing false positives on data-list patterns.
func (f *xmlMaintFrame) isHomogeneousList() bool {
	if f.homogeneityUnknown {
		return true // Suppress finding if we couldn't properly track ratios
	}
	if f.directChildCount == 0 {
		return false
	}
	var dominantCount int
	for _, cnt := range f.directChildCounts {
		if cnt > dominantCount {
			dominantCount = cnt
		}
	}
	return dominantCount*100 >= f.directChildCount*80
}

// ─── Namespace scope ──────────────────────────────────────────────────────────

type xmlNSBinding struct {
	uri  string
	decl *xmlNSDecl
}

type xmlNSScope struct {
	frames []map[string]xmlNSBinding
}

func (s *xmlNSScope) push(m map[string]xmlNSBinding) {
	s.frames = append(s.frames, m)
}

func (s *xmlNSScope) pop() {
	if len(s.frames) > 0 {
		s.frames = s.frames[:len(s.frames)-1]
	}
}

func (s *xmlNSScope) resolve(prefix string) (xmlNSBinding, bool) {
	if prefix == "xml" {
		return xmlNSBinding{uri: "http://www.w3.org/XML/1998/namespace"}, true
	}
	if prefix == "xmlns" {
		return xmlNSBinding{uri: "http://www.w3.org/2000/xmlns/"}, true
	}
	for i := len(s.frames) - 1; i >= 0; i-- {
		if binding, ok := s.frames[i][prefix]; ok {
			return binding, true
		}
	}
	return xmlNSBinding{}, false
}

func (s *xmlNSScope) parentURI(prefix string) (string, bool) {
	for i := len(s.frames) - 1; i >= 0; i-- {
		if binding, ok := s.frames[i][prefix]; ok {
			return binding.uri, true
		}
	}
	return "", false
}

// ─── Schema state ────────────────────────────────────────────────────────────

type schemaLocationPair struct {
	namespace string
	uri       string
	line      int
}

type xmlSchemaState struct {
	hasDoctype              bool
	hasNoNSSchemaLocation   bool
	usedNoNamespaceElement  bool
	schemaLocationPairs     []schemaLocationPair
	usedNamespaces          map[string]struct{}
	noNSSchemaLocationAttrs []int // lines
}

// ─── Fast line offset computation ─────────────────────────────────────────────

func computeNewlineOffsets(content []byte) []int {
	var offsets []int
	for i, b := range content {
		if b == '\n' {
			offsets = append(offsets, i)
		}
	}
	return offsets
}

func xmlByteLineNumber(offsets []int, pos int) int {
	if pos < 0 {
		return 1
	}
	idx := sort.SearchInts(offsets, pos)
	return 1 + idx
}

// ─── Main scanner ─────────────────────────────────────────────────────────────

func scanXMLMaintainability(rel string, content []byte) []ports.CodeAnalysisRawFinding {
	col := newXMLMaintainabilityCollector()
	nlOffsets := computeNewlineOffsets(content)

	scanXMLMaintainabilityLexical(rel, content, nlOffsets, col)
	scanXMLMaintainabilityStructural(rel, content, nlOffsets, col)

	sortXMLFindings(col.findings)
	return col.findings
}

// ─── Structural pass ─────────────────────────────────────────────────────────

func scanXMLMaintainabilityStructural(rel string, content []byte, nlOffsets []int, col *xmlMaintainabilityCollector) {
	dec := xml.NewDecoder(bytes.NewReader(content))
	dec.Strict = false
	dec.AutoClose = nil

	var stack []*xmlMaintFrame
	scope := &xmlNSScope{}

	schema := &xmlSchemaState{
		usedNamespaces: make(map[string]struct{}),
	}

	depth := 0
	nestingReported := false
	rootSeen := false
	rootLine := 0

	uriToUsedPrefixes := make(map[string]map[string]struct{})
	multiplePrefixReported := make(map[string]bool)

	markPrefixUsed := func(prefix, uri string) {
		if uri == "" || prefix == "" {
			return
		}
		if uriToUsedPrefixes[uri] == nil {
			uriToUsedPrefixes[uri] = make(map[string]struct{})
		}
		uriToUsedPrefixes[uri][prefix] = struct{}{}
	}

	checkMultiplePrefixes := func(uri string, line int) {
		if uri == "" || multiplePrefixReported[uri] {
			return
		}
		if len(uriToUsedPrefixes[uri]) >= 2 {
			multiplePrefixReported[uri] = true
			prefixes := make([]string, 0, len(uriToUsedPrefixes[uri]))
			for p := range uriToUsedPrefixes[uri] {
				prefixes = append(prefixes, p)
			}
			sort.Strings(prefixes)
			col.add(xmlRawFinding(
				xmlMultiplePrefixesSameNamespaceRuleID,
				rel, line,
				fmt.Sprintf("Namespace %q is bound to multiple prefixes (%s), which reduces readability.",
					truncateXMLDiagnosticValue(uri, 120),
					truncateXMLDiagnosticValue(strings.Join(prefixes, ", "), 120),
				),
			))
		}
	}

	resolveAndMark := func(prefix, localName string, line int) string {
		if prefix == "xmlns" || prefix == "xml" {
			return ""
		}
		binding, _ := scope.resolve(prefix)
		uri := binding.uri
		if prefix != "" {
			if uri != "" {
				schema.usedNamespaces[uri] = struct{}{}
				markPrefixUsed(prefix, uri)
				checkMultiplePrefixes(uri, line)
				if binding.decl != nil {
					binding.decl.used = true
				}
			}
		} else {
			if uri != "" {
				schema.usedNamespaces[uri] = struct{}{}
				if binding.decl != nil {
					binding.decl.used = true
				}
			} else {
				schema.usedNoNamespaceElement = true
			}
		}
		return uri
	}

	for {
		offset := dec.InputOffset()
		tok, err := dec.RawToken()
		if err != nil {
			break
		}

		switch t := tok.(type) {
		case xml.Directive:
			directive := strings.TrimSpace(string(t))
			if strings.HasPrefix(directive, "DOCTYPE") {
				schema.hasDoctype = true
			}
		case xml.StartElement:
			endOffset := dec.InputOffset()
			startOffset := offset
			for startOffset < int64(len(content)) && content[startOffset] != '<' {
				startOffset++
			}
			line := xmlByteLineNumber(nlOffsets, int(startOffset))

			if rootLine == 0 {
				rootLine = line
			}

			depth++

			tagSlice := content[startOffset:endOffset]
			attrOffsets := make(map[string]int)
			j := 0
			// Skip tag name
			for j < len(tagSlice) && tagSlice[j] != ' ' && tagSlice[j] != '\t' && tagSlice[j] != '\n' && tagSlice[j] != '\r' && tagSlice[j] != '>' {
				j++
			}
			for j < len(tagSlice) {
				for j < len(tagSlice) && (tagSlice[j] == ' ' || tagSlice[j] == '\t' || tagSlice[j] == '\n' || tagSlice[j] == '\r') {
					j++
				}
				if j >= len(tagSlice) || tagSlice[j] == '>' || tagSlice[j] == '/' {
					break
				}
				attrStart := j
				for j < len(tagSlice) && tagSlice[j] != '=' && tagSlice[j] != ' ' && tagSlice[j] != '\t' && tagSlice[j] != '\n' && tagSlice[j] != '\r' && tagSlice[j] != '>' {
					j++
				}
				name := string(tagSlice[attrStart:j])
				for j < len(tagSlice) && tagSlice[j] != '=' {
					j++
				}
				if j < len(tagSlice) && tagSlice[j] == '=' {
					j++
					for j < len(tagSlice) && (tagSlice[j] == ' ' || tagSlice[j] == '\t' || tagSlice[j] == '\n' || tagSlice[j] == '\r') {
						j++
					}
					if j < len(tagSlice) && (tagSlice[j] == '"' || tagSlice[j] == '\'') {
						q := tagSlice[j]
						j++
						for j < len(tagSlice) && tagSlice[j] != q {
							j++
						}
						j++
					}
				}
				attrOffsets[name] = int(startOffset) + attrStart
			}

			type declEntry struct {
				prefix string
				uri    string
			}
			var declEntries []declEntry

			for _, attr := range t.Attr {
				if attr.Name.Space == "xmlns" {
					declEntries = append(declEntries, declEntry{prefix: attr.Name.Local, uri: attr.Value})
				} else if attr.Name.Space == "" && attr.Name.Local == "xmlns" {
					declEntries = append(declEntries, declEntry{prefix: "", uri: attr.Value})
				}
			}

			frame := newXMLMaintFrame("", line, depth)

			for _, de := range declEntries {
				prefix := de.prefix
				uri := de.uri
				parentURI, parentHas := scope.parentURI(prefix)

				attrName := "xmlns"
				if prefix != "" {
					attrName = "xmlns:" + prefix
				}
				attrLine := line
				if off, ok := attrOffsets[attrName]; ok {
					attrLine = xmlByteLineNumber(nlOffsets, off)
				}

				decl := &xmlNSDecl{
					prefix:       prefix,
					uri:          uri,
					inheritedURI: parentURI,
					line:         attrLine,
				}

				if prefix == "xml" || prefix == "xmlns" {
					decl.reserved = true
					decl.used = true
				} else if prefix == "" && uri == "" {
					decl.reserved = true
					decl.used = true
				} else {
					if parentHas {
						if parentURI == uri {
							decl.redundant = true
						} else if prefix != "" {
							decl.shadowing = true
						}
					}
				}

				frame.decls = append(frame.decls, decl)
			}

			scopeMap := make(map[string]xmlNSBinding)
			for _, decl := range frame.decls {
				scopeMap[decl.prefix] = xmlNSBinding{uri: decl.uri, decl: decl}
			}
			scope.push(scopeMap)

			for _, decl := range frame.decls {
				if decl.reserved {
					continue
				}
				switch {
				case decl.redundant:
					if decl.prefix == "" {
						col.add(xmlRawFinding(
							xmlRedundantNamespaceDeclarationRuleID, rel, decl.line,
							fmt.Sprintf("Default namespace declaration repeats the inherited binding to %q and can be removed.",
								truncateXMLDiagnosticValue(decl.uri, 120)),
						))
					} else {
						col.add(xmlRawFinding(
							xmlRedundantNamespaceDeclarationRuleID, rel, decl.line,
							fmt.Sprintf("Namespace prefix %q repeats the inherited binding to %q and can be removed.",
								decl.prefix, truncateXMLDiagnosticValue(decl.uri, 120)),
						))
					}
				case decl.shadowing:
					col.add(xmlRawFinding(
						xmlNamespacePrefixShadowingRuleID, rel, decl.line,
						fmt.Sprintf("Namespace prefix %q is rebound from %q to %q in a nested scope.",
							decl.prefix,
							truncateXMLDiagnosticValue(decl.inheritedURI, 120),
							truncateXMLDiagnosticValue(decl.uri, 120)),
					))
				}
			}

			elemPrefix := t.Name.Space
			elemLocalName := t.Name.Local
			elemQName := elemLocalName
			if elemPrefix != "" {
				elemQName = elemPrefix + ":" + elemLocalName
			}
			frame.qname = elemQName

			_ = resolveAndMark(elemPrefix, elemLocalName, line)

			nonNSAttrCount := 0
			for _, attr := range t.Attr {
				attrPrefix := attr.Name.Space
				attrLocal := attr.Name.Local

				if attrPrefix == "xmlns" || (attrPrefix == "" && attrLocal == "xmlns") {
					continue
				}

				nonNSAttrCount++

				if attrPrefix != "" && attrPrefix != "xml" {
					attrURI := resolveAndMark(attrPrefix, attrLocal, line)
					if attrURI == xsiInstanceURI {
						switch attrLocal {
						case "noNamespaceSchemaLocation":
							schema.hasNoNSSchemaLocation = true
							attrLine := line
							attrQName := attrLocal
							if attrPrefix != "" {
								attrQName = attrPrefix + ":" + attrLocal
							}
							if off, ok := attrOffsets[attrQName]; ok {
								attrLine = xmlByteLineNumber(nlOffsets, off)
							}
							schema.noNSSchemaLocationAttrs = append(schema.noNSSchemaLocationAttrs, attrLine)
						case "schemaLocation":
							pairs := strings.Fields(attr.Value)
							attrLine := line
							attrQName := attrLocal
							if attrPrefix != "" {
								attrQName = attrPrefix + ":" + attrLocal
							}
							if off, ok := attrOffsets[attrQName]; ok {
								attrLine = xmlByteLineNumber(nlOffsets, off)
							}
							for i := 0; i+1 < len(pairs); i += 2 {
								schema.schemaLocationPairs = append(schema.schemaLocationPairs, schemaLocationPair{
									namespace: pairs[i],
									uri:       pairs[i+1],
									line:      attrLine,
								})
							}
						}
					}
				}
			}

			if nonNSAttrCount > xmlMaxAttributesPerElement {
				col.add(xmlRawFinding(
					xmlTooManyAttributesRuleID, rel, line,
					fmt.Sprintf("Element <%s> defines %d non-namespace attributes; threshold is %d.",
						truncateXMLDiagnosticValue(elemQName, 120),
						nonNSAttrCount,
						xmlMaxAttributesPerElement),
				))
			}

			if !nestingReported && depth > xmlMaxMaintainableDepth {
				nestingReported = true
				col.add(xmlRawFinding(
					xmlExcessiveNestingDepthRuleID, rel, line,
					fmt.Sprintf("XML structure reaches a nesting depth of %d; threshold is %d.", depth, xmlMaxMaintainableDepth),
				))
			}

			if !rootSeen {
				rootSeen = true
			}

			if len(stack) > 0 {
				stack[len(stack)-1].addDirectChild(elemQName)
			}

			stack = append(stack, frame)

		case xml.EndElement:
			if len(stack) == 0 {
				depth--
				scope.pop()
				continue
			}

			frame := stack[len(stack)-1]
			stack = stack[:len(stack)-1]

			closeLine := xmlByteLineNumber(nlOffsets, int(dec.InputOffset()))
			depth--

			if frame.directChildCount > xmlMaxDirectChildren &&
				len(frame.distinctDirectNames) >= xmlMinDistinctChildNames &&
				!frame.isHomogeneousList() {
				col.add(xmlRawFinding(
					xmlTooManyChildElementsRuleID, rel, frame.startLine,
					fmt.Sprintf("Element <%s> has %d direct children across %d distinct names; threshold is %d children with %d names.",
						truncateXMLDiagnosticValue(frame.qname, 120),
						frame.directChildCount,
						len(frame.distinctDirectNames),
						xmlMaxDirectChildren,
						xmlMinDistinctChildNames),
				))
			}

			lineSpan := closeLine - frame.startLine + 1
			if lineSpan > xmlOversizedElementLineSpan &&
				frame.descendantCount >= xmlOversizedElementMinDescendants &&
				len(frame.distinctDescNames) >= xmlOversizedElementMinDistinctNames &&
				!frame.isHomogeneousList() {
				col.add(xmlRawFinding(
					xmlOversizedElementRuleID, rel, frame.startLine,
					fmt.Sprintf("Element <%s> spans %d lines and contains %d descendant elements across %d element names.",
						truncateXMLDiagnosticValue(frame.qname, 120),
						lineSpan,
						frame.descendantCount,
						len(frame.distinctDescNames)),
				))
			}

			for _, decl := range frame.decls {
				if decl.reserved || decl.redundant || decl.shadowing {
					continue
				}
				if !decl.used {
					if decl.prefix == "" {
						col.add(xmlRawFinding(
							xmlUnusedNamespaceDeclarationRuleID, rel, decl.line,
							fmt.Sprintf("Default namespace declaration %q is never used in its scope.",
								truncateXMLDiagnosticValue(decl.uri, 120)),
						))
					} else {
						col.add(xmlRawFinding(
							xmlUnusedNamespaceDeclarationRuleID, rel, decl.line,
							fmt.Sprintf("Namespace prefix %q declared as %q is never used in its scope.",
								decl.prefix,
								truncateXMLDiagnosticValue(decl.uri, 120)),
						))
					}
				}
			}

			if len(stack) > 0 {
				stack[len(stack)-1].mergeDescendant(frame)
			}

			scope.pop()
		}
	}

	checkXMLSchemaFindings(rel, schema, col, rootSeen, rootLine)
}

func checkXMLSchemaFindings(
	rel string,
	schema *xmlSchemaState,
	col *xmlMaintainabilityCollector,
	rootSeen bool,
	rootLine int,
) {
	if rootLine == 0 {
		rootLine = 1
	}

	hasAssociation := schema.hasDoctype || schema.hasNoNSSchemaLocation || len(schema.schemaLocationPairs) > 0

	if rootSeen && !hasAssociation {
		col.add(xmlRawFinding(
			xmlSchemaMissingRuleID, rel, rootLine,
			"XML document has no schema association (no DOCTYPE, xsi:schemaLocation, or xsi:noNamespaceSchemaLocation).",
		))
	}

	seenNS := make(map[string]bool)
	reportedDuplicate := make(map[string]bool)
	for _, pair := range schema.schemaLocationPairs {
		ns := pair.namespace
		if seenNS[ns] && !reportedDuplicate[ns] {
			col.add(xmlRawFinding(
				xmlDuplicateSchemaNamespaceRuleID, rel, pair.line,
				fmt.Sprintf("Namespace %q appears more than once in xsi:schemaLocation.",
					truncateXMLDiagnosticValue(ns, 120)),
			))
			reportedDuplicate[ns] = true
		}
		seenNS[ns] = true
	}

	reportedUnused := make(map[string]bool)
	for _, pair := range schema.schemaLocationPairs {
		ns := pair.namespace
		if reportedUnused[ns] {
			continue
		}
		reportedUnused[ns] = true
		if _, used := schema.usedNamespaces[ns]; !used {
			col.add(xmlRawFinding(
				xmlUnusedSchemaLocationRuleID, rel, pair.line,
				fmt.Sprintf("Schema location entry for namespace %q is never used in the document.",
					truncateXMLDiagnosticValue(ns, 120)),
			))
		}
	}

	if schema.hasNoNSSchemaLocation && !schema.usedNoNamespaceElement {
		for _, attrLine := range schema.noNSSchemaLocationAttrs {
			col.add(xmlRawFinding(
				xmlUnusedSchemaLocationRuleID, rel, attrLine,
				"xsi:noNamespaceSchemaLocation is declared but no element belongs to the no-namespace.",
			))
		}
	}
}

// ─── Lexical pass (comments, CDATA) ──────────────────────────────────────────

func scanXMLMaintainabilityLexical(rel string, content []byte, nlOffsets []int, col *xmlMaintainabilityCollector) {
	i := 0
	n := len(content)

	type lexicalState int
	const (
		stateNormal lexicalState = iota
		statePI
		stateDTD
		stateDTDQuoted
	)
	state := stateNormal
	dtdDepth := 0
	var dtdQuoteChar byte

	for i < n {
		switch state {
		case statePI:
			if i+1 < n && content[i] == '?' && content[i+1] == '>' {
				state = stateNormal
				i += 2
			} else {
				i++
			}
			continue
		case stateDTDQuoted:
			if content[i] == dtdQuoteChar {
				state = stateDTD
			}
			i++
			continue
		case stateDTD:
			if content[i] == '"' || content[i] == '\'' {
				state = stateDTDQuoted
				dtdQuoteChar = content[i]
				i++
				continue
			}
			if i+3 < n && content[i] == '<' && content[i+1] == '!' && content[i+2] == '-' && content[i+3] == '-' {
				start := i
				i += 4
				bodyStart := i
				end := -1
				for j := i; j+2 < n; j++ {
					if content[j] == '-' && content[j+1] == '-' && content[j+2] == '>' {
						end = j
						break
					}
				}
				if end < 0 {
					break // unfinished comment
				}
				body := content[bodyStart:end]
				commentLine := xmlByteLineNumber(nlOffsets, start)
				analyzeXMLComment(rel, body, commentLine, col)
				i = end + 3
				continue
			}
			if content[i] == '[' {
				dtdDepth++
				i++
				continue
			}
			if content[i] == ']' {
				dtdDepth--
				i++
				continue
			}
			if content[i] == '>' && dtdDepth <= 0 {
				state = stateNormal
				i++
				continue
			}
			i++
			continue
		}

		// stateNormal processing
		if content[i] != '<' {
			i++
			continue
		}

		if i+1 < n && content[i+1] == '?' {
			state = statePI
			i += 2
			continue
		}

		if i+8 < n && bytes.Equal(content[i+1:i+9], []byte("!DOCTYPE")) {
			state = stateDTD
			dtdDepth = 0
			i += 9
			continue
		}

		if i+3 < n && content[i+1] == '!' && content[i+2] == '-' && content[i+3] == '-' {
			start := i
			i += 4
			bodyStart := i
			end := -1
			for j := i; j+2 < n; j++ {
				if content[j] == '-' && content[j+1] == '-' && content[j+2] == '>' {
					end = j
					break
				}
			}
			if end < 0 {
				break
			}
			body := content[bodyStart:end]
			commentLine := xmlByteLineNumber(nlOffsets, start)

			analyzeXMLComment(rel, body, commentLine, col)

			i = end + 3
			continue
		}

		if i+8 < n && bytes.Equal(content[i+1:i+9], []byte("![CDATA[")) {
			start := i
			i += 9
			bodyStart := i
			end := -1
			for j := i; j+2 < n; j++ {
				if content[j] == ']' && content[j+1] == ']' && content[j+2] == '>' {
					end = j
					break
				}
			}
			if end < 0 {
				break
			}
			body := content[bodyStart:end]
			cdataLine := xmlByteLineNumber(nlOffsets, start)

			trimmed := bytes.TrimSpace(body)
			if len(trimmed) > 0 && !bytes.ContainsAny(trimmed, "<&") {
				col.add(xmlRawFinding(
					xmlRedundantCDATASectionRuleID, rel, cdataLine,
					"CDATA section contains no markup-sensitive characters (no '<' or '&') and can be replaced with plain text.",
				))
			}

			i = end + 3
			continue
		}

		i++
	}
}

func analyzeXMLComment(
	rel string,
	body []byte,
	openingLine int,
	col *xmlMaintainabilityCollector,
) {
	byteLen := len(body)
	lineCount := 1 + bytes.Count(body, []byte("\n"))
	if byteLen > xmlMaxCommentBytes || lineCount > xmlMaxCommentLines {
		col.add(xmlRawFinding(
			xmlOversizedCommentRuleID, rel, openingLine,
			fmt.Sprintf("XML comment is %d bytes and %d lines; thresholds are %d bytes or %d lines.",
				byteLen, lineCount, xmlMaxCommentBytes, xmlMaxCommentLines),
		))
	}

	checkCommentedOutMarkup(rel, body, openingLine, col)
}

func checkCommentedOutMarkup(
	rel string,
	body []byte,
	commentLine int,
	col *xmlMaintainabilityCollector,
) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return
	}
	if trimmed[0] != '<' || trimmed[len(trimmed)-1] != '>' {
		return
	}

	probe := body
	if len(probe) > xmlMaxCommentedMarkupProbeBytes {
		return
	}

	const syntheticOpen = "<x-synth-root>"
	const syntheticClose = "</x-synth-root>"
	fragment := []byte(syntheticOpen)
	fragment = append(fragment, probe...)
	fragment = append(fragment, []byte(syntheticClose)...)

	dec := xml.NewDecoder(bytes.NewReader(fragment))

	depth := 0
	hasInnerElement := false
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return
		}

		switch tok.(type) {
		case xml.StartElement:
			depth++
			if depth > 1 {
				hasInnerElement = true
			}
		case xml.EndElement:
			depth--
		}
	}

	if hasInnerElement {
		col.add(xmlRawFinding(
			xmlCommentedOutMarkupRuleID, rel, commentLine,
			"XML comment contains what appears to be commented-out markup.",
		))
	}
}
