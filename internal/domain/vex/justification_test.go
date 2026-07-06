package vex

import "testing"

func TestOpenVexJustificationValid(t *testing.T) {
	for _, j := range []OpenVexJustification{
		ComponentNotPresent, VulnerableCodeNotPresent, VulnerableCodeNotInExecutePath,
		VulnerableCodeCannotBeControlled, InlineMitigationsAlreadyExist,
	} {
		if !j.Valid() {
			t.Errorf("%q must be a valid OpenVEX justification", j)
		}
	}
	for _, j := range []string{"", "bogus", "not_affected", "COMPONENT_NOT_PRESENT", "vulnerable_code_not_present "} {
		if OpenVexJustification(j).Valid() {
			t.Errorf("%q must be invalid (fail-closed)", j)
		}
	}
}
