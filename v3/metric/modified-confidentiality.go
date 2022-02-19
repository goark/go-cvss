package metric

import "strings"

//ModifiedConfidentialityImpact is metric type for Base Metrics
type ModifiedConfidentialityImpact int

//Constant of ModifiedConfidentialityImpact result
const (
	ModifiedConfidentialityImpactNotDefined ModifiedConfidentialityImpact = iota
	ModifiedConfidentialityImpactNone
	ModifiedConfidentialityImpactLow
	ModifiedConfidentialityImpactHigh
)

var ModifiedConfidentialityImpactMap = map[ModifiedConfidentialityImpact]string{
	ModifiedConfidentialityImpactNotDefined: "X",
	ModifiedConfidentialityImpactNone:       "N",
	ModifiedConfidentialityImpactLow:        "L",
	ModifiedConfidentialityImpactHigh:       "H",
}

var ModifiedConfidentialityImpactValueMap = map[ModifiedConfidentialityImpact]float64{
	ModifiedConfidentialityImpactNotDefined: 0.00,
	ModifiedConfidentialityImpactNone:       0.00,
	ModifiedConfidentialityImpactLow:        0.22,
	ModifiedConfidentialityImpactHigh:       0.56,
}

//GetModifiedConfidentialityImpact returns result of ModifiedConfidentialityImpact metric
func GetModifiedConfidentialityImpact(s string) ModifiedConfidentialityImpact {
	s = strings.ToUpper(s)
	for k, v := range ModifiedConfidentialityImpactMap {
		if s == v {
			return k
		}
	}
	return ModifiedConfidentialityImpactNotDefined
}

func (mci ModifiedConfidentialityImpact) String() string {
	if s, ok := ModifiedConfidentialityImpactMap[mci]; ok {
		return s
	}
	return ""
}

//Value returns value of ModifiedConfidentialityImpact metric
func (mci ModifiedConfidentialityImpact) Value(ci ConfidentialityImpact) float64 {
	if mci.String() == ModifiedAttackComplexityNotDefined.String() {
		if v, ok := confidentialityImpactValueMap[ci]; ok {
			return v
		}
		return 0.0
	} else {
		if v, ok := ModifiedConfidentialityImpactValueMap[mci]; ok {
			return v
		}
		return 0.0
	}

}

//IsDefined returns false if undefined result value of metric
func (mci ModifiedConfidentialityImpact) IsDefined() bool {
	_, ok := ModifiedConfidentialityImpactValueMap[mci]
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
