package metric

import "strings"

//AttackVector is metric type for Base Metrics
type IntegrityRequirement int

//Constant of AttackVector result
const (
	IntegrityRequirementNotDefined IntegrityRequirement = iota
	IntegrityRequirementLow
	IntegrityRequirementMedium
	IntegrityRequirementHigh
)

var IntegrityRequirementMap = map[IntegrityRequirement]string{
	IntegrityRequirementNotDefined: "X",
	IntegrityRequirementLow:        "L",
	IntegrityRequirementMedium:     "M",
	IntegrityRequirementHigh:       "H",
}

var IntegrityRequirementValueMap = map[IntegrityRequirement]float64{
	IntegrityRequirementNotDefined: 1,
	IntegrityRequirementLow:        0.5,
	IntegrityRequirementMedium:     1,
	IntegrityRequirementHigh:       1.5,
}

//GetIntegrityRequirement returns result of ConfidentalityRequirement metric
func GetIntegrityRequirement(s string) IntegrityRequirement {
	s = strings.ToUpper(s)
	for k, v := range IntegrityRequirementMap {
		if s == v {
			return k
		}
	}
	return IntegrityRequirementNotDefined
}

func (ir IntegrityRequirement) String() string {
	if s, ok := IntegrityRequirementMap[ir]; ok {
		return s
	}
	return ""
}

//Value returns value of AttackVector metric
func (ir IntegrityRequirement) Value() float64 {
	if v, ok := IntegrityRequirementValueMap[ir]; ok {
		return v
	}
	return 0.0
}

//IsDefined returns false if undefined result value of metric
func (ir IntegrityRequirement) IsDefined() bool {
	_, ok := IntegrityRequirementValueMap[ir]
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
