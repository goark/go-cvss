package base

import "strings"

//ModifiedScope is metric type for Base Metrics
type ModifiedScope int

//Constant of ModifiedScope result
const (
	ModifiedScopeNotDefined ModifiedScope = iota
	ModifiedScopeUnchanged
	ModifiedScopeChanged
)

var ModifiedScopeMap = map[ModifiedScope]string{
	ModifiedScopeNotDefined: "X",
	ModifiedScopeUnchanged:  "U",
	ModifiedScopeChanged:    "C",
}

//GetModifiedScope returns result of ModifiedScope metric
func GetModifiedScope(s string) ModifiedScope {
	s = strings.ToUpper(s)
	for k, v := range ModifiedScopeMap {
		if s == v {
			return k
		}
	}
	return ModifiedScopeNotDefined
}

func (msc ModifiedScope) String() string {
	if s, ok := ModifiedScopeMap[msc]; ok {
		return s
	}
	return ""
}

//IsDefined returns false if undefined result value of metric
func (msc ModifiedScope) IsDefined() bool {
	return msc != ModifiedScopeNotDefined
}

/* Copyright 2022 thejohnbrown */
