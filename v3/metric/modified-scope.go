package metric

import "strings"

//ModifiedScope is metric type for Base Metrics
type ModifiedScope int

//Constant of ModifiedScope result
const (
	ModifiedScopeNotDefined ModifiedScope = iota
	ModifiedScopeUnchanged
	ModifiedScopeChanged
)

var ModifiedScopeValueMap = map[ModifiedScope]string{
	ModifiedScopeNotDefined: "X",
	ModifiedScopeUnchanged:  "U",
	ModifiedScopeChanged:    "C",
}

//GetModifiedScope returns result of ModifiedScope metric
func GetModifiedScope(s string) ModifiedScope {
	s = strings.ToUpper(s)
	for k, v := range ModifiedScopeValueMap {
		if s == v {
			return k
		}
	}
	return ModifiedScopeNotDefined
}

func (msc ModifiedScope) String() string {
	if s, ok := ModifiedScopeValueMap[msc]; ok {
		return s
	}
	return ""
}

//IsDefined returns false if undefined result value of metric
func (msc ModifiedScope) IsDefined() bool {
	_, ok := ModifiedScopeValueMap[msc]
	return ok
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
