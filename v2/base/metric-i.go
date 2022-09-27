package base

import "strings"

// IntegrityImpact is metric type for Base Metrics
type IntegrityImpact int

// Constant of IntegrityImpact result
const (
	IntegrityImpactUnknown IntegrityImpact = iota
	IntegrityImpactNone
	IntegrityImpactPartial
	IntegrityImpactComplete
)

var integrityImpactMap = map[IntegrityImpact]string{
	IntegrityImpactNone:     "N",
	IntegrityImpactPartial:  "P",
	IntegrityImpactComplete: "C",
}

var integrityImpactValueMap = map[IntegrityImpact]float64{
	IntegrityImpactNone:     0,
	IntegrityImpactPartial:  0.275,
	IntegrityImpactComplete: 0.66,
}

// GetIntegrityImpact returns result of IntegrityImpact metric
func GetIntegrityImpact(s string) IntegrityImpact {
	s = strings.ToUpper(s)
	for k, v := range integrityImpactMap {
		if s == v {
			return k
		}
	}
	return IntegrityImpactUnknown
}

func (ii IntegrityImpact) String() string {
	if s, ok := integrityImpactMap[ii]; ok {
		return s
	}
	return ""
}

// Value returns value of IntegrityImpact metric
func (ii IntegrityImpact) Value() float64 {
	if v, ok := integrityImpactValueMap[ii]; ok {
		return v
	}
	return 0.0
}

// IsDefined returns false if undefined result value of metric
func (ii IntegrityImpact) IsDefined() bool {
	return ii != IntegrityImpactUnknown
}

/* Copyright 2022 luxifer */
