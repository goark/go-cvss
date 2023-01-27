package metric

// ModifiedScope is metric type for Base Metrics
type ModifiedScope int

// Constant of ModifiedScope result
const (
	ModifiedScopeInvalid ModifiedScope = iota
	ModifiedScopeNotDefined
	ModifiedScopeUnchanged
	ModifiedScopeChanged
)

var ModifiedScopeValueMap = map[ModifiedScope]string{
	ModifiedScopeNotDefined: "X",
	ModifiedScopeUnchanged:  "U",
	ModifiedScopeChanged:    "C",
}

// GetModifiedScope returns result of ModifiedScope metric
func GetModifiedScope(s string) ModifiedScope {
	for k, v := range ModifiedScopeValueMap {
		if s == v {
			return k
		}
	}
	return ModifiedScopeInvalid
}

func (msc ModifiedScope) String() string {
	if s, ok := ModifiedScopeValueMap[msc]; ok {
		return s
	}
	return ""
}

// IsDefined returns false if undefined result value of metric
func (msc ModifiedScope) IsValid() bool {
	_, ok := ModifiedScopeValueMap[msc]
	return ok
}

/* Copyright 2022 thejohnbrown */
/* Contributed by Spiegel, 2023 */
