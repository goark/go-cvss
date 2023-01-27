package base

// AccessComplexity is metric type for Base Metrics
type AccessComplexity int

// Constant of AccessComplexity result
const (
	AccessComplexityUnknown AccessComplexity = iota
	AccessComplexityHigh
	AccessComplexityMedium
	AccessComplexityLow
)

var accessComplexityMap = map[AccessComplexity]string{
	AccessComplexityHigh:   "H",
	AccessComplexityMedium: "M",
	AccessComplexityLow:    "L",
}

var accessComplexityValueMap = map[AccessComplexity]float64{
	AccessComplexityHigh:   0.35,
	AccessComplexityMedium: 0.61,
	AccessComplexityLow:    0.71,
}

// GetAccessComplexity returns result of AccessComplexity metric
func GetAccessComplexity(s string) AccessComplexity {
	for k, v := range accessComplexityMap {
		if s == v {
			return k
		}
	}
	return AccessComplexityUnknown
}

func (ac AccessComplexity) String() string {
	if s, ok := accessComplexityMap[ac]; ok {
		return s
	}
	return ""
}

// Value returns value of AccessComplexity metric
func (ac AccessComplexity) Value() float64 {
	if v, ok := accessComplexityValueMap[ac]; ok {
		return v
	}
	return 0.0
}

// IsDefined returns false if undefined result value of metric
func (ac AccessComplexity) IsDefined() bool {
	return ac != AccessComplexityUnknown
}

/* Copyright 2022 luxifer */
/* Contributed by Spiegel, 2023 */
