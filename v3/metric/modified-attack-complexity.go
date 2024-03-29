package metric

// ModifiedAttackComplexity is metric type for Base Metrics
type ModifiedAttackComplexity int

// Constant of ModifiedAttackComplexity result
const (
	ModifiedAttackComplexityInvalid ModifiedAttackComplexity = iota
	ModifiedAttackComplexityNotDefined
	ModifiedAttackComplexityHigh
	ModifiedAttackComplexityLow
)

var ModifiedAttackComplexityMap = map[ModifiedAttackComplexity]string{
	ModifiedAttackComplexityNotDefined: "X",
	ModifiedAttackComplexityHigh:       "H",
	ModifiedAttackComplexityLow:        "L",
}

var ModifiedAttackComplexityValueMap = map[ModifiedAttackComplexity]float64{
	ModifiedAttackComplexityNotDefined: 0,
	ModifiedAttackComplexityHigh:       0.44,
	ModifiedAttackComplexityLow:        0.77,
}

// GetModifiedAttackComplexity returns result of ModifiedAttackComplexity metric
func GetModifiedAttackComplexity(s string) ModifiedAttackComplexity {
	for k, v := range ModifiedAttackComplexityMap {
		if s == v {
			return k
		}
	}
	return ModifiedAttackComplexityInvalid
}

func (mac ModifiedAttackComplexity) String() string {
	if s, ok := ModifiedAttackComplexityMap[mac]; ok {
		return s
	}
	return ""
}

// Value returns value of ModifiedAttackComplexity metric
func (mac ModifiedAttackComplexity) Value(ac AttackComplexity) float64 {
	if mac == ModifiedAttackComplexityNotDefined {
		if v, ok := attackComplexityValueMap[ac]; ok {
			return v
		}
		return 0.0
	} else {
		if v, ok := ModifiedAttackComplexityValueMap[mac]; ok {
			return v
		}
		return 0.0
	}
}

// IsDefined returns false if undefined result value of metric
func (mac ModifiedAttackComplexity) IsValid() bool {
	_, ok := ModifiedAttackComplexityValueMap[mac]
	return ok
}

/* Copyright 2022 thejohnbrown */
/* Contributed by Spiegel, 2023 */
