package base

import "strings"

//Exploitability is metric type for Temporal Metrics
type Exploitability int

//Constant of Exploitability result
const (
	ExploitabilityNotDefined Exploitability = iota
	ExploitabilityUnproven
	ExploitabilityProofOfConcept
	ExploitabilityFunctional
	ExploitabilityHigh
)

var ExploitabilityMap = map[Exploitability]string{
	ExploitabilityNotDefined:     "X",
	ExploitabilityUnproven:       "U",
	ExploitabilityProofOfConcept: "P",
	ExploitabilityFunctional:     "F",
	ExploitabilityHigh:           "H",
}

var ExploitabilityValueMap = map[Exploitability]float64{
	ExploitabilityNotDefined:     1,
	ExploitabilityUnproven:       0.91,
	ExploitabilityProofOfConcept: 0.94,
	ExploitabilityFunctional:     0.97,
	ExploitabilityHigh:           1,
}

//GetExploitability returns result of Exploitability metric
func GetExploitability(s string) Exploitability {
	s = strings.ToUpper(s)
	for k, v := range ExploitabilityMap {
		if s == v {
			return k
		}
	}
	return ExploitabilityNotDefined
}

func (ai Exploitability) String() string {
	if s, ok := ExploitabilityMap[ai]; ok {
		return s
	}
	return ""
}

//Value returns value of Exploitability metric
func (ai Exploitability) Value() float64 {
	if v, ok := ExploitabilityValueMap[ai]; ok {
		return v
	}
	return 1
}

//IsDefined returns false if undefined result value of metric
func (ai Exploitability) IsDefined() bool {
	return ai != ExploitabilityNotDefined
}
