package codeanalysis

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestXMLStructural_MismatchedTag(t *testing.T) {
	content := []byte(`<root><item></other></item></root>`)
	findings := scanXMLStructural("test.xml", content, -1).Findings

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].RuleID != xmlMismatchedTagRuleID {
		t.Errorf("expected %s, got %s", xmlMismatchedTagRuleID, findings[0].RuleID)
	}
	if findings[0].Line != 1 {
		t.Errorf("expected line 1, got %d", findings[0].Line)
	}
}

func TestXMLStructural_MismatchedTagOnly(t *testing.T) {
	content := []byte(`<root><item></root>`)
	findings := scanXMLStructural("test.xml", content, -1).Findings

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].RuleID != xmlMismatchedTagRuleID {
		t.Errorf("expected %s, got %s", xmlMismatchedTagRuleID, findings[0].RuleID)
	}
}

func TestXMLStructural_UnclosedElement(t *testing.T) {
	content := []byte(`<root><item>`)
	findings := scanXMLStructural("test.xml", content, -1).Findings

	if len(findings) != 1 {
		t.Fatalf("expected 1 unclosed element finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].RuleID != xmlUnclosedElementRuleID {
		t.Errorf("expected xml:unclosed-element")
	}
}

func TestXMLStructural_MultipleRootElements(t *testing.T) {
	content := []byte(`<first/><second/>`)
	findings := scanXMLStructural("test.xml", content, -1).Findings

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != xmlMultipleRootElementsRuleID {
		t.Errorf("expected %s, got %s", xmlMultipleRootElementsRuleID, findings[0].RuleID)
	}
}

func TestXMLStructural_UndeclaredPrefix(t *testing.T) {
	content := []byte(`<root><cfg:item/></root>`)
	findings := scanXMLStructural("test.xml", content, -1).Findings

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != xmlUndeclaredPrefixRuleID {
		t.Errorf("expected %s, got %s", xmlUndeclaredPrefixRuleID, findings[0].RuleID)
	}
}

func TestXMLStructural_DeclaredPrefix(t *testing.T) {
	content := []byte(`<root xmlns:cfg="http://example.com"><cfg:item/></root>`)
	findings := scanXMLStructural("test.xml", content, -1).Findings
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestXMLStructural_InvalidCharacterReference(t *testing.T) {
	tests := []struct {
		xml      string
		expected int
	}{
		{`&#12</root>`, 1},
		{`&#X20;`, 1},
		{`&#;`, 1},
		{`&#x;`, 1},
		{`&#x20;`, 0},
		{`&#32;`, 0},
		{`&#999999999999999999999999;`, 1},
	}

	for _, tc := range tests {
		t.Run(tc.xml, func(t *testing.T) {
			content := []byte(`<root>` + tc.xml + `</root>`)
			findings := scanXMLStructural("test.xml", content, -1).Findings
			count := 0
			for _, f := range findings {
				if f.RuleID == xmlInvalidCharacterReferenceRuleID {
					count++
				}
			}
			if count != tc.expected {
				t.Errorf("expected %d findings for %q, got %d: %+v", tc.expected, tc.xml, count, findings)
			}
		})
	}
}

func TestXMLStructural_InvalidComment(t *testing.T) {
	tests := []struct {
		xml      string
		expected int
	}{
		{`<!-- invalid -- comment -->`, 1},
		{`<!-- invalid --->`, 1},
		{`<!-- unfinished`, 1},
		{`<root><!-- unfinished`, 1},
		{`<!-- valid comment -->`, 0},
	}

	for _, tc := range tests {
		t.Run(tc.xml, func(t *testing.T) {
			content := []byte(tc.xml)
			findings := scanXMLStructural("test.xml", content, -1).Findings
			count := 0
			for _, f := range findings {
				if f.RuleID == xmlInvalidCommentRuleID {
					count++
				}
			}
			if count != tc.expected {
				t.Errorf("expected %d findings for %q, got %d: %+v", tc.expected, tc.xml, count, findings)
			}
		})
	}
}

func TestXMLStructural_CharRefLineTracking(t *testing.T) {
	content := []byte(`<root password="
&#0;
&#1;
"/>`)
	findings := scanXMLStructural("test.xml", content, -1).Findings
	var charRefFindings []ports.CodeAnalysisRawFinding
	for _, f := range findings {
		if f.RuleID == xmlInvalidCharacterReferenceRuleID {
			charRefFindings = append(charRefFindings, f)
		}
	}

	if len(charRefFindings) != 1 {
		t.Fatalf("expected 1 invalid char ref, got %d: %+v", len(charRefFindings), charRefFindings)
	}
	if charRefFindings[0].Line != 2 {
		t.Errorf("expected first char ref on line 2, got line %d", charRefFindings[0].Line)
	}
}

func TestXMLStructural_AttributeLineTracking(t *testing.T) {
	content := []byte(`<root
  p:value="1"/>`)
	findings := scanXMLStructural("test.xml", content, -1).Findings
	var prefixFinding *ports.CodeAnalysisRawFinding
	for _, f := range findings {
		if f.RuleID == xmlUndeclaredPrefixRuleID {
			prefixFinding = &f
		}
	}
	if prefixFinding == nil {
		t.Fatalf("expected undeclared prefix finding, got: %+v", findings)
	}
	if prefixFinding.Line != 2 {
		t.Errorf("expected undeclared prefix on line 2, got line %d", prefixFinding.Line)
	}

	content2 := []byte(`<root xmlns:a="urn:x" xmlns:b="urn:x"
  a:value="1"
  b:value="2"/>`)
	findings2 := scanXMLStructural("test.xml", content2, -1).Findings
	var dupFinding *ports.CodeAnalysisRawFinding
	for _, f := range findings2 {
		if f.RuleID == xmlDuplicateAttributeRuleID {
			dupFinding = &f
		}
	}
	if dupFinding == nil {
		t.Fatalf("expected duplicate attribute finding, got: %+v", findings2)
	}
	if dupFinding.Line != 3 {
		t.Errorf("expected duplicate attribute on line 3, got line %d", dupFinding.Line)
	}
}

func TestXMLStructural_DTD(t *testing.T) {
	content := []byte(`<!DOCTYPE root [
  <!ELEMENT root (#PCDATA)>
  <!ENTITY x "ok">
]>
<root>&x;</root>`)
	findings := scanXMLStructural("test.xml", content, -1).Findings
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for valid DTD, got %d: %+v", len(findings), findings)
	}
}

func TestXMLStructural_DuplicateExpandedAttributes(t *testing.T) {
	content := []byte(`<root xmlns:a="urn:test" xmlns:b="urn:test" a:val="1" b:val="2"/>`)
	findings := scanXMLStructural("test.xml", content, -1).Findings
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].RuleID != xmlDuplicateAttributeRuleID {
		t.Errorf("expected %s, got %s", xmlDuplicateAttributeRuleID, findings[0].RuleID)
	}
}

func TestXMLStructural_DTDComments(t *testing.T) {
	content := []byte(`<!DOCTYPE root [
  <!-- ] > -->
  <!ELEMENT root EMPTY>
]>
<root/>`)
	findings := scanXMLStructural("test.xml", content, -1).Findings
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for valid DTD with comment, got %d: %+v", len(findings), findings)
	}
}

func TestXMLStructural_DuplicateAttributesUndeclared(t *testing.T) {
	content := []byte(`<root a:x="1" b:x="2"/>`)
	findings := scanXMLStructural("test.xml", content, -1).Findings
	dupCount := 0
	for _, f := range findings {
		if f.RuleID == xmlDuplicateAttributeRuleID {
			dupCount++
		}
	}
	if dupCount != 0 {
		t.Fatalf("expected 0 duplicate attributes for undeclared prefixes, got %d", dupCount)
	}
}
