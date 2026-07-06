package shared

import (
	"math"
	"strings"
)

// CVSSv3BaseScore computes the CVSS v3.0/v3.1 base score from a vector string
// (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"). Returns (score, true) for
// a well-formed v3 vector, else (0, false). v4.0 vectors are not scored here.
func CVSSv3BaseScore(vector string) (float64, bool) {
	vector = strings.TrimSpace(vector)
	v31 := strings.HasPrefix(vector, "CVSS:3.1/")
	if !v31 && !strings.HasPrefix(vector, "CVSS:3.0/") {
		return 0, false
	}
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/")[1:] {
		if k, v, found := strings.Cut(part, ":"); found {
			m[k] = v
		}
	}
	scopeChanged := m["S"] == "C"

	av, ok1 := metricAV[m["AV"]]
	ac, ok2 := metricAC[m["AC"]]
	ui, ok3 := metricUI[m["UI"]]
	pr, ok4 := privilegesRequired(m["PR"], scopeChanged)
	c, ok5 := metricImpact[m["C"]]
	i, ok6 := metricImpact[m["I"]]
	a, ok7 := metricImpact[m["A"]]
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return 0, false
	}

	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	switch {
	case !scopeChanged:
		impact = 6.42 * iss
	case v31:
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss*0.9731-0.02, 13)
	default: // v3.0, scope changed
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}

	expl := 8.22 * av * ac * pr * ui
	sum := impact + expl
	if scopeChanged {
		sum *= 1.08
	}
	return roundUpCVSS(math.Min(sum, 10), v31), true
}

var (
	metricAV     = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
	metricAC     = map[string]float64{"L": 0.77, "H": 0.44}
	metricUI     = map[string]float64{"N": 0.85, "R": 0.62}
	metricImpact = map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
)

func privilegesRequired(pr string, scopeChanged bool) (float64, bool) {
	switch pr {
	case "N":
		return 0.85, true
	case "L":
		if scopeChanged {
			return 0.68, true
		}
		return 0.62, true
	case "H":
		if scopeChanged {
			return 0.50, true
		}
		return 0.27, true
	default:
		return 0, false
	}
}

// roundUpCVSS rounds up to one decimal place per the CVSS spec (v3.1 uses
// integer arithmetic to avoid float artifacts; v3.0 uses ceil(x*10)/10).
func roundUpCVSS(x float64, v31 bool) float64 {
	if !v31 {
		return math.Ceil(x*10) / 10
	}
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000.0
	}
	return (math.Floor(float64(i)/10000) + 1) / 10.0
}

// SeverityFromScore maps a CVSS base score to the qualitative severity band.
func SeverityFromScore(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score >= 0.1:
		return SeverityLow
	default:
		return SeverityInfo
	}
}
