package metric

import "strings"

//ModifiedIntegrityImpact is metric type for Base Metrics
type ModifiedIntegrityImpact int

//Constant of ModifiedIntegrityImpact result
const (
	ModifiedIntegrityImpactNotDefined ModifiedIntegrityImpact = iota
	ModifiedIntegrityImpactNone
	ModifiedIntegrityImpactLow
	ModifiedIntegrityImpactHigh
)

var ModifiedIntegrityImpactMap = map[ModifiedIntegrityImpact]string{
	ModifiedIntegrityImpactNotDefined: "X",
	ModifiedIntegrityImpactNone:       "N",
	ModifiedIntegrityImpactLow:        "L",
	ModifiedIntegrityImpactHigh:       "H",
}

var ModifiedIntegrityImpactValueMap = map[ModifiedIntegrityImpact]float64{
	ModifiedIntegrityImpactNotDefined: 0.00,
	ModifiedIntegrityImpactNone:       0.00,
	ModifiedIntegrityImpactLow:        0.22,
	ModifiedIntegrityImpactHigh:       0.56,
}

//GetModifiedIntegrityImpact returns result of ModifiedIntegrityImpact metric
func GetModifiedIntegrityImpact(s string) ModifiedIntegrityImpact {
	s = strings.ToUpper(s)
	for k, v := range ModifiedIntegrityImpactMap {
		if s == v {
			return k
		}
	}
	return ModifiedIntegrityImpactNotDefined
}

func (mii ModifiedIntegrityImpact) String() string {
	if s, ok := ModifiedIntegrityImpactMap[mii]; ok {
		return s
	}
	return ""
}

//Value returns value of ModifiedIntegrityImpact metric
func (mii ModifiedIntegrityImpact) Value(ii IntegrityImpact) float64 {
	if mii.String() == ModifiedAttackComplexityNotDefined.String() {
		if v, ok := integrityImpactValueMap[ii]; ok {
			return v
		}
		return 0.0
	} else {
		if v, ok := ModifiedIntegrityImpactValueMap[mii]; ok {
			return v
		}
		return 0.0
	}
}

//IsDefined returns false if undefined result value of metric
func (mii ModifiedIntegrityImpact) IsDefined() bool {
	_, ok := ModifiedIntegrityImpactValueMap[mii]
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
