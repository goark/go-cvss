package metric

// IntegrityRequirement is metric type for Base Metrics
type IntegrityRequirement int

// Constant of IntegrityRequirement result
const (
	IntegrityRequirementInvalid IntegrityRequirement = iota
	IntegrityRequirementNotDefined
	IntegrityRequirementLow
	IntegrityRequirementMedium
	IntegrityRequirementHigh
)

var IntegrityRequirementMap = map[IntegrityRequirement]string{
	IntegrityRequirementNotDefined: "X",
	IntegrityRequirementLow:        "L",
	IntegrityRequirementMedium:     "M",
	IntegrityRequirementHigh:       "H",
}

var IntegrityRequirementValueMap = map[IntegrityRequirement]float64{
	IntegrityRequirementNotDefined: 1,
	IntegrityRequirementLow:        0.5,
	IntegrityRequirementMedium:     1,
	IntegrityRequirementHigh:       1.5,
}

// GetIntegrityRequirement returns result of ConfidentalityRequirement metric
func GetIntegrityRequirement(s string) IntegrityRequirement {
	for k, v := range IntegrityRequirementMap {
		if s == v {
			return k
		}
	}
	return IntegrityRequirementInvalid
}

func (ir IntegrityRequirement) String() string {
	if s, ok := IntegrityRequirementMap[ir]; ok {
		return s
	}
	return ""
}

// Value returns value of AttackVector metric
func (ir IntegrityRequirement) Value() float64 {
	if v, ok := IntegrityRequirementValueMap[ir]; ok {
		return v
	}
	return 0.0
}

// IsDefined returns false if undefined result value of metric
func (ir IntegrityRequirement) IsValid() bool {
	_, ok := IntegrityRequirementValueMap[ir]
	return ok
}

/* Copyright 2022 thejohnbrown */
/* Contributed by Spiegel, 2023 */
