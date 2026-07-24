//go:build cgo

package astwalk

import (
	"strings"
)

func computeCSSSelectorSpecificity(sel string) (classAttrPseudo int, typePseudoElem int) {
	specificity := computeCSSSelectorSpecificityAtDepth(sel, 0)
	return specificity.Classes, specificity.Types
}

type cssSpecificity struct {
	IDs     int
	Classes int
	Types   int
}

func (s cssSpecificity) add(other cssSpecificity) cssSpecificity {
	return cssSpecificity{
		IDs:     s.IDs + other.IDs,
		Classes: s.Classes + other.Classes,
		Types:   s.Types + other.Types,
	}
}

func (s cssSpecificity) less(other cssSpecificity) bool {
	if s.IDs != other.IDs {
		return s.IDs < other.IDs
	}
	if s.Classes != other.Classes {
		return s.Classes < other.Classes
	}
	return s.Types < other.Types
}

func computeCSSSelectorSpecificityAtDepth(sel string, depth int) cssSpecificity {
	if depth >= cssMaxSelectorDepth {
		return cssSpecificity{}
	}

	cleanSel := sel
	total := cssSpecificity{}

	for {
		fn := nextCSSSpecificityPseudo(cleanSel)
		if fn == "" {
			break
		}
		remaining, extracted, ok := extractAndRemoveCSSPseudoFunction(cleanSel, fn)
		if !ok {
			break
		}
		cleanSel = remaining
		if fn == ":where(" {
			continue
		}

		maxArg := cssSpecificity{}
		for _, arg := range splitCSSTopLevelCommas(extracted) {
			arg = strings.TrimSpace(arg)
			if arg == "" {
				continue
			}
			argSpecificity := computeCSSSelectorSpecificityAtDepth(arg, depth+1)
			if maxArg.less(argSpecificity) {
				maxArg = argSpecificity
			}
		}
		total = total.add(maxArg)
	}

	for _, token := range tokenizeCSSSelector(cleanSel) {
		if strings.HasPrefix(token, ".") || strings.HasPrefix(token, "[") {
			total.Classes++
		} else if strings.HasPrefix(token, "#") {
			total.IDs++
		} else if strings.HasPrefix(token, "::") {
			total.Types++
		} else if strings.HasPrefix(token, ":") {
			if isLegacyPseudoElemToken(token) {
				total.Types++
			} else {
				total.Classes++
			}
		} else if token != "*" && token != "" && !isCombinatorToken(token) {
			total.Types++
		}
	}

	return total
}

func nextCSSSpecificityPseudo(sel string) string {
	next := ""
	nextIndex := len(sel)
	for _, fn := range []string{":where(", ":is(", ":not(", ":has("} {
		if idx := findCSSPseudoFunction(sel, fn); idx >= 0 && idx < nextIndex {
			next, nextIndex = fn, idx
		}
	}
	return next
}

func extractAndRemoveCSSPseudoFunction(sel, fn string) (remaining string, argsStr string, ok bool) {
	idx := findCSSPseudoFunction(sel, fn)
	if idx == -1 {
		return sel, "", false
	}
	start := idx + len(fn)
	depth := 1
	end := start
	inString := false
	quote := byte(0)
	escaped := false
	bracketDepth := 0
	for end < len(sel) && depth > 0 {
		b := sel[end]
		if escaped {
			escaped = false
			end++
			continue
		}
		if inString {
			if b == '\\' {
				escaped = true
			} else if b == quote {
				inString = false
			}
			end++
			continue
		}
		if b == '\'' || b == '"' {
			inString, quote = true, b
		} else if b == '[' {
			bracketDepth++
		} else if b == ']' && bracketDepth > 0 {
			bracketDepth--
		} else if bracketDepth == 0 && b == '(' {
			depth++
		} else if bracketDepth == 0 && b == ')' {
			depth--
		}
		end++
	}
	if depth != 0 {
		return sel, "", false
	}
	argsStr = sel[start : end-1]
	remaining = sel[:idx] + sel[end:]
	return remaining, argsStr, true
}

func findCSSPseudoFunction(sel, fn string) int {
	inString := false
	quote := byte(0)
	escaped := false
	bracketDepth := 0

	for i := 0; i < len(sel); i++ {
		b := sel[i]
		if escaped {
			escaped = false
			continue
		}
		if b == '\\' {
			escaped = true
			continue
		}
		if inString {
			if b == quote {
				inString = false
			}
			continue
		}
		if b == '\'' || b == '"' {
			inString, quote = true, b
			continue
		}
		if b == '[' {
			bracketDepth++
			continue
		}
		if b == ']' && bracketDepth > 0 {
			bracketDepth--
			continue
		}
		if bracketDepth == 0 && strings.HasPrefix(sel[i:], fn) {
			return i
		}
	}
	return -1
}

func removeCSSPseudoFunction(sel, fn string) string {
	for findCSSPseudoFunction(sel, fn) >= 0 {
		remaining, _, ok := extractAndRemoveCSSPseudoFunction(sel, fn)
		if !ok {
			break
		}
		sel = remaining
	}
	return sel
}

func isLegacyPseudoElemToken(tok string) bool {
	name := strings.TrimPrefix(tok, ":")
	return cssLegacyPseudoElements[name]
}

func isCombinatorToken(tok string) bool {
	return tok == " " || tok == ">" || tok == "+" || tok == "~" || tok == "||"
}

func tokenizeCSSSelector(sel string) []string {
	var tokens []string
	var current strings.Builder

	inBracket := false

	for i := 0; i < len(sel); i++ {
		b := sel[i]

		if b == '[' {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			inBracket = true
			current.WriteByte(b)
			continue
		}
		if b == ']' {
			current.WriteByte(b)
			tokens = append(tokens, current.String())
			current.Reset()
			inBracket = false
			continue
		}

		if inBracket {
			current.WriteByte(b)
			continue
		}

		if b == '.' || b == '#' || b == ':' {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			current.WriteByte(b)
			continue
		}

		if b == ' ' || b == '>' || b == '+' || b == '~' {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			tokens = append(tokens, string(b))
			continue
		}

		current.WriteByte(b)
	}

	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	var res []string
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t != "" {
			res = append(res, t)
		}
	}
	return res
}

func computeCSSSelectorDepth(sel string) int {
	parts := splitCSSCompoundSelectors(sel)
	depth := len(parts)
	if depth > cssMaxSelectorDepth {
		return cssMaxSelectorDepth
	}
	return depth
}

func splitCSSCompoundSelectors(sel string) []string {
	var segments []string
	var current strings.Builder

	parenDepth := 0
	bracketDepth := 0
	inString := false
	quoteChar := byte(0)

	for i := 0; i < len(sel); i++ {
		b := sel[i]

		if inString {
			if b == quoteChar {
				inString = false
			}
			current.WriteByte(b)
			continue
		}
		if b == '\'' || b == '"' {
			inString = true
			quoteChar = b
			current.WriteByte(b)
			continue
		}

		if b == '(' {
			parenDepth++
			current.WriteByte(b)
			continue
		}
		if b == ')' {
			if parenDepth > 0 {
				parenDepth--
			}
			current.WriteByte(b)
			continue
		}
		if b == '[' {
			bracketDepth++
			current.WriteByte(b)
			continue
		}
		if b == ']' {
			if bracketDepth > 0 {
				bracketDepth--
			}
			current.WriteByte(b)
			continue
		}

		if parenDepth == 0 && bracketDepth == 0 {
			if b == ' ' || b == '>' || b == '+' || b == '~' {
				if current.Len() > 0 {
					segments = append(segments, current.String())
					current.Reset()
				}
				continue
			}
		}

		current.WriteByte(b)
	}

	if current.Len() > 0 {
		segments = append(segments, current.String())
	}

	var res []string
	for _, s := range segments {
		s = strings.TrimSpace(s)
		if s != "" {
			res = append(res, s)
		}
	}
	return res
}

func countCSSTopLevelSelectors(prelude string) int {
	items := splitCSSTopLevelCommas(prelude)
	return len(items)
}

func splitCSSTopLevelCommas(prelude string) []string {
	var items []string
	var current strings.Builder

	parenDepth := 0
	bracketDepth := 0
	inString := false
	quoteChar := byte(0)

	for i := 0; i < len(prelude); i++ {
		b := prelude[i]

		if inString {
			if b == quoteChar {
				inString = false
			}
			current.WriteByte(b)
			continue
		}
		if b == '\'' || b == '"' {
			inString = true
			quoteChar = b
			current.WriteByte(b)
			continue
		}

		if b == '(' {
			parenDepth++
			current.WriteByte(b)
			continue
		}
		if b == ')' {
			if parenDepth > 0 {
				parenDepth--
			}
			current.WriteByte(b)
			continue
		}
		if b == '[' {
			bracketDepth++
			current.WriteByte(b)
			continue
		}
		if b == ']' {
			if bracketDepth > 0 {
				bracketDepth--
			}
			current.WriteByte(b)
			continue
		}

		if parenDepth == 0 && bracketDepth == 0 && b == ',' {
			items = append(items, current.String())
			current.Reset()
			continue
		}

		current.WriteByte(b)
	}

	if current.Len() > 0 {
		items = append(items, current.String())
	}

	return items
}

func hasCSSIDSelector(sel string) bool {
	clean := removeCSSPseudoFunction(sel, ":where(")
	tokens := tokenizeCSSSelector(clean)
	for _, t := range tokens {
		if strings.HasPrefix(t, "#") {
			return true
		}
	}
	return false
}

func isCSSOverqualifiedSelector(sel string) bool {
	return isCSSOverqualifiedSelectorAtDepth(sel, 0)
}

func isCSSOverqualifiedSelectorAtDepth(sel string, depth int) bool {
	if depth >= cssMaxSelectorDepth {
		return false
	}

	clean := sel
	for {
		fn := nextCSSSpecificityPseudo(clean)
		if fn == "" {
			break
		}
		remaining, extracted, ok := extractAndRemoveCSSPseudoFunction(clean, fn)
		if !ok {
			break
		}
		if fn != ":where(" {
			for _, arg := range splitCSSTopLevelCommas(extracted) {
				if isCSSOverqualifiedSelectorAtDepth(strings.TrimSpace(arg), depth+1) {
					return true
				}
			}
		}
		clean = remaining
	}

	compounds := splitCSSCompoundSelectors(clean)
	for _, comp := range compounds {
		tokens := tokenizeCSSSelector(comp)
		hasType := false
		hasClassOrID := false

		for _, t := range tokens {
			if t == "*" || strings.Contains(t, "|") {
				continue
			}
			if strings.HasPrefix(t, ".") || strings.HasPrefix(t, "#") {
				hasClassOrID = true
			} else if !strings.HasPrefix(t, ":") && !strings.HasPrefix(t, "[") {
				hasType = true
			}
		}

		if hasType && hasClassOrID {
			return true
		}
	}
	return false
}

func hasCSSLegacyPseudoElement(sel string) (string, bool) {
	bracketDepth := 0
	for i := 0; i < len(sel); {
		if sel[i] == '\\' {
			i += 2
			continue
		}
		if sel[i] == '\'' || sel[i] == '"' {
			next, ok := skipCSSQuoted(sel, i)
			if !ok {
				return "", false
			}
			i = next
			continue
		}
		switch sel[i] {
		case '[':
			bracketDepth++
			i++
			continue
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
			i++
			continue
		case ':':
			if bracketDepth > 0 || (i > 0 && sel[i-1] == ':') || (i+1 < len(sel) && sel[i+1] == ':') {
				i++
				continue
			}
			nameStart := i + 1
			nameEnd := scanCSSIdentifier(sel, nameStart)
			if nameEnd > nameStart {
				name := strings.ToLower(sel[nameStart:nameEnd])
				if cssLegacyPseudoElements[name] && (nameEnd == len(sel) || sel[nameEnd] != '\\') {
					return name, true
				}
				i = nameEnd
				continue
			}
		}
		i++
	}
	return "", false
}
