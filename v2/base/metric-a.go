package base

// AvailabilityImpact is metric type for Base Metrics
type AvailabilityImpact int

// Constant of AvailabilityImpact result
const (
	AvailabilityImpactUnknown AvailabilityImpact = iota
	AvailabilityImpactNone
	AvailabilityImpactPartial
	AvailabilityImpactComplete
)

var availabilityImpactMap = map[AvailabilityImpact]string{
	AvailabilityImpactNone:     "N",
	AvailabilityImpactPartial:  "P",
	AvailabilityImpactComplete: "C",
}

var availabilityImpactValueMap = map[AvailabilityImpact]float64{
	AvailabilityImpactNone:     0,
	AvailabilityImpactPartial:  0.275,
	AvailabilityImpactComplete: 0.66,
}

// GetAvailabilityImpact returns result of AvailabilityImpact metric
func GetAvailabilityImpact(s string) AvailabilityImpact {
	for k, v := range availabilityImpactMap {
		if s == v {
			return k
		}
	}
	return AvailabilityImpactUnknown
}

func (ai AvailabilityImpact) String() string {
	if s, ok := availabilityImpactMap[ai]; ok {
		return s
	}
	return ""
}

// Value returns value of AvailabilityImpact metric
func (ai AvailabilityImpact) Value() float64 {
	if v, ok := availabilityImpactValueMap[ai]; ok {
		return v
	}
	return 0.0
}

// IsDefined returns false if undefined result value of metric
func (ai AvailabilityImpact) IsDefined() bool {
	return ai != AvailabilityImpactUnknown
}

/* Copyright 2022 luxifer */
/* Contributed by Spiegel, 2023 */
