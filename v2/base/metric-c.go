package base

// ConfidentialityImpact is metric type for Base Metrics
type ConfidentialityImpact int

// Constant of ConfidentialityImpact result
const (
	ConfidentialityImpactUnknown ConfidentialityImpact = iota
	ConfidentialityImpactNone
	ConfidentialityImpactPartial
	ConfidentialityImpactComplete
)

var confidentialityImpactMap = map[ConfidentialityImpact]string{
	ConfidentialityImpactNone:     "N",
	ConfidentialityImpactPartial:  "P",
	ConfidentialityImpactComplete: "C",
}

var confidentialityImpactValueMap = map[ConfidentialityImpact]float64{
	ConfidentialityImpactNone:     0,
	ConfidentialityImpactPartial:  0.275,
	ConfidentialityImpactComplete: 0.66,
}

// GetConfidentialityImpact returns result of ConfidentialityImpact metric
func GetConfidentialityImpact(s string) ConfidentialityImpact {
	for k, v := range confidentialityImpactMap {
		if s == v {
			return k
		}
	}
	return ConfidentialityImpactUnknown
}

func (ci ConfidentialityImpact) String() string {
	if s, ok := confidentialityImpactMap[ci]; ok {
		return s
	}
	return ""
}

// Value returns value of ConfidentialityImpact metric
func (ci ConfidentialityImpact) Value() float64 {
	if v, ok := confidentialityImpactValueMap[ci]; ok {
		return v
	}
	return 0.0
}

// IsDefined returns false if undefined result value of metric
func (ci ConfidentialityImpact) IsDefined() bool {
	return ci != ConfidentialityImpactUnknown
}

/* Copyright 2022 luxifer */
/* Contributed by Spiegel, 2023 */
