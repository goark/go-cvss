package base

// Authentication is metric type for Base Metrics
type Authentication int

// Constant of Authentication result
const (
	AuthenticationUnknown Authentication = iota
	AuthenticationNone
	AuthenticationSingle
	AuthenticationMultiple
)

var authenticationMap = map[Authentication]string{
	AuthenticationNone:     "N",
	AuthenticationSingle:   "S",
	AuthenticationMultiple: "M",
}

var authenticationValueMap = map[Authentication]float64{
	AuthenticationNone:     0.704,
	AuthenticationSingle:   0.56,
	AuthenticationMultiple: 0.45,
}

// GetAuthentication returns result of Authentication metric
func GetAuthentication(s string) Authentication {
	for k, v := range authenticationMap {
		if s == v {
			return k
		}
	}
	return AuthenticationUnknown
}

func (av Authentication) String() string {
	if s, ok := authenticationMap[av]; ok {
		return s
	}
	return ""
}

// Value returns value of Authentication metric
func (av Authentication) Value() float64 {
	if v, ok := authenticationValueMap[av]; ok {
		return v
	}
	return 0.0
}

// IsDefined returns false if undefined result value of metric
func (av Authentication) IsDefined() bool {
	return av != AuthenticationUnknown
}

/* Copyright 2022 luxifer */
/* Contributed by Spiegel, 2023 */
