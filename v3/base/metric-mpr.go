package base

import "strings"

//ModifiedPrivilegesRequired is metric type for Base Metrics
type ModifiedPrivilegesRequired int

//Constant of ModifiedPrivilegesRequired result
const (
	ModifiedPrivilegesRequiredUnknown ModifiedPrivilegesRequired = iota
	ModifiedPrivilegesRequiredNotDefined
	ModifiedPrivilegesRequiredHigh
	ModifiedPrivilegesRequiredLow
	ModifiedPrivilegesRequiredNone
)

var ModifiedPrivilegesRequiredMap = map[ModifiedPrivilegesRequired]string{
	ModifiedPrivilegesRequiredNotDefined: "X",
	ModifiedPrivilegesRequiredHigh:       "H",
	ModifiedPrivilegesRequiredLow:        "L",
	ModifiedPrivilegesRequiredNone:       "N",
}

var ModifiedPrivilegesRequiredWithUValueMap = map[ModifiedPrivilegesRequired]float64{
	ModifiedPrivilegesRequiredNotDefined: 0.85,
	ModifiedPrivilegesRequiredHigh:       0.27,
	ModifiedPrivilegesRequiredLow:        0.62,
	ModifiedPrivilegesRequiredNone:       0.85,
}
var ModifiedPrivilegesRequiredWithCValueMap = map[ModifiedPrivilegesRequired]float64{
	ModifiedPrivilegesRequiredNotDefined: 0.85,
	ModifiedPrivilegesRequiredHigh:       0.50,
	ModifiedPrivilegesRequiredLow:        0.68,
	ModifiedPrivilegesRequiredNone:       0.85,
}

//GetModifiedPrivilegesRequired returns result of ModifiedPrivilegesRequired metric
func GetModifiedPrivilegesRequired(s string) ModifiedPrivilegesRequired {
	s = strings.ToUpper(s)
	for k, v := range ModifiedPrivilegesRequiredMap {
		if s == v {
			return k
		}
	}
	return ModifiedPrivilegesRequiredNotDefined
}

func (mpr ModifiedPrivilegesRequired) String() string {
	if s, ok := ModifiedPrivilegesRequiredMap[mpr]; ok {
		return s
	}
	return ""
}

//Value returns value of ModifiedPrivilegesRequired metric
func (mpr ModifiedPrivilegesRequired) Value(s Scope) float64 {
	var m map[ModifiedPrivilegesRequired]float64
	switch s {
	case ScopeUnchanged:
		m = ModifiedPrivilegesRequiredWithUValueMap
	case ScopeChanged:
		m = ModifiedPrivilegesRequiredWithCValueMap
	default:
		return 0.0
	}
	if v, ok := m[mpr]; ok {
		return v
	}
	return 0.0
}

//IsDefined returns false if undefined result value of metric
func (mpr ModifiedPrivilegesRequired) IsDefined() bool {
	return mpr != ModifiedPrivilegesRequiredNotDefined
}

/* Copyright 2018 Spiegel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
