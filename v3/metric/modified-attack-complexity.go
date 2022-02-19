package metric

import "strings"

//ModifiedAttackComplexity is metric type for Base Metrics
type ModifiedAttackComplexity int

//Constant of ModifiedAttackComplexity result
const (
	ModifiedAttackComplexityNotDefined ModifiedAttackComplexity = iota
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

//GetModifiedAttackComplexity returns result of ModifiedAttackComplexity metric
func GetModifiedAttackComplexity(s string) ModifiedAttackComplexity {
	s = strings.ToUpper(s)
	for k, v := range ModifiedAttackComplexityMap {
		if s == v {
			return k
		}
	}
	return ModifiedAttackComplexityNotDefined
}

func (mac ModifiedAttackComplexity) String() string {
	if s, ok := ModifiedAttackComplexityMap[mac]; ok {
		return s
	}
	return ""
}

//Value returns value of ModifiedAttackComplexity metric
func (mac ModifiedAttackComplexity) Value(ac AttackComplexity) float64 {
	if mac.String() == ModifiedAttackComplexityNotDefined.String() {
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

//IsDefined returns false if undefined result value of metric
func (mac ModifiedAttackComplexity) IsDefined() bool {
	_, ok := ModifiedAttackComplexityValueMap[mac]
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
