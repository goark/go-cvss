package base

// AccessVector is metric type for Base Metrics
type AccessVector int

// Constant of AccessVector result
const (
	AccessVectorUnknown AccessVector = iota
	AccessVectorLocal
	AccessVectorAdjacent
	AccessVectorNetwork
)

var accessVectorMap = map[AccessVector]string{
	AccessVectorLocal:    "L",
	AccessVectorAdjacent: "A",
	AccessVectorNetwork:  "N",
}

var accessVectorValueMap = map[AccessVector]float64{
	AccessVectorLocal:    0.395,
	AccessVectorAdjacent: 0.646,
	AccessVectorNetwork:  1,
}

// GetAccessVector returns result of AccessVector metric
func GetAccessVector(s string) AccessVector {
	for k, v := range accessVectorMap {
		if s == v {
			return k
		}
	}
	return AccessVectorUnknown
}

func (av AccessVector) String() string {
	if s, ok := accessVectorMap[av]; ok {
		return s
	}
	return ""
}

// Value returns value of AccessVector metric
func (av AccessVector) Value() float64 {
	if v, ok := accessVectorValueMap[av]; ok {
		return v
	}
	return 0.0
}

// IsDefined returns false if undefined result value of metric
func (av AccessVector) IsDefined() bool {
	return av != AccessVectorUnknown
}

/* Copyright 2022 luxifer */
/* Contributed by Spiegel, 2023 */
