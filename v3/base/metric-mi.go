package base

import "strings"

//ModifiedIntegrityImpact is metric type for Base Metrics
type ModifiedIntegrityImpact int

//Constant of ModifiedIntegrityImpact result
const (
	ModifiedIntegrityImpactNotDefined ModifiedIntegrityImpact = iota
	ModifiedIntegrityImpactNone
	ModifiedIntegrityImpactLow
	ModifiedIntegrityImpactHigh
)

var ModifiedIntegrityImpactMap = map[ModifiedIntegrityImpact]string{
	ModifiedIntegrityImpactNotDefined: "X",
	ModifiedIntegrityImpactNone:       "N",
	ModifiedIntegrityImpactLow:        "L",
	ModifiedIntegrityImpactHigh:       "H",
}

var ModifiedIntegrityImpactValueMap = map[ModifiedIntegrityImpact]float64{
	ModifiedIntegrityImpactNone: 0.00,
	ModifiedIntegrityImpactLow:  0.22,
	ModifiedIntegrityImpactHigh: 0.56,
}

//GetModifiedIntegrityImpact returns result of ModifiedIntegrityImpact metric
func GetModifiedIntegrityImpact(s string) ModifiedIntegrityImpact {
	s = strings.ToUpper(s)
	for k, v := range ModifiedIntegrityImpactMap {
		if s == v {
			return k
		}
	}
	return ModifiedIntegrityImpactNotDefined
}

func (mii ModifiedIntegrityImpact) String() string {
	if s, ok := ModifiedIntegrityImpactMap[mii]; ok {
		return s
	}
	return ""
}

//Value returns value of ModifiedIntegrityImpact metric
func (mii ModifiedIntegrityImpact) Value() float64 {
	if v, ok := ModifiedIntegrityImpactValueMap[mii]; ok {
		return v
	}
	return 0.0
}

//IsDefined returns false if undefined result value of metric
func (mii ModifiedIntegrityImpact) IsDefined() bool {
	return mii != ModifiedIntegrityImpactNotDefined
}

/* Copyright 2022 thejohnbrown */
