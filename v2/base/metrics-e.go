package base

import "strings"

// Exploitability is metric type for Temporal Metrics
type Exploitability int

// Constant of Exploitability result
const (
	ExploitabilityNotDefined Exploitability = iota
	ExploitabilityUnproven
	ExploitabilityProofOfConcept
	ExploitabilityFunctional
	ExploitabilityHigh
)

var exploitabilityMap = map[Exploitability]string{
	ExploitabilityNotDefined:     "ND",
	ExploitabilityUnproven:       "U",
	ExploitabilityProofOfConcept: "POC",
	ExploitabilityFunctional:     "F",
	ExploitabilityHigh:           "H",
}

var exploitabilityValueMap = map[Exploitability]float64{
	ExploitabilityNotDefined:     1,
	ExploitabilityUnproven:       0.85,
	ExploitabilityProofOfConcept: 0.9,
	ExploitabilityFunctional:     0.95,
	ExploitabilityHigh:           1,
}

// GetExploitability returns result of Exploitability metric
func GetExploitability(s string) Exploitability {
	s = strings.ToUpper(s)
	for k, v := range exploitabilityMap {
		if s == v {
			return k
		}
	}
	return ExploitabilityNotDefined
}

func (ai Exploitability) String() string {
	if s, ok := exploitabilityMap[ai]; ok {
		return s
	}
	return ""
}

// Value returns value of Exploitability metric
func (ai Exploitability) Value() float64 {
	if v, ok := exploitabilityValueMap[ai]; ok {
		return v
	}
	return 1
}

// IsDefined returns false if undefined result value of metric
func (ai Exploitability) IsDefined() bool {
	return ai != ExploitabilityNotDefined
}

/* Copyright 2022 luxifer */
