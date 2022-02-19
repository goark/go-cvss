package metric

import "strings"

//AttackVector is metric type for Base Metrics
type ConfidentialityRequirement int

//Constant of AttackVector result
const (
	ConfidentialityRequirementNotDefined ConfidentialityRequirement = iota
	ConfidentialityRequirementLow
	ConfidentialityRequirementMedium
	ConfidentialityRequirementHigh
)

var ConfidentialityRequirementMap = map[ConfidentialityRequirement]string{
	ConfidentialityRequirementNotDefined: "X",
	ConfidentialityRequirementLow:        "L",
	ConfidentialityRequirementMedium:     "M",
	ConfidentialityRequirementHigh:       "H",
}

var ConfidentialityRequirementValueMap = map[ConfidentialityRequirement]float64{
	ConfidentialityRequirementNotDefined: 1,
	ConfidentialityRequirementLow:        0.5,
	ConfidentialityRequirementMedium:     1,
	ConfidentialityRequirementHigh:       1.5,
}

//GetConfidentialityRequirement returns result of ConfidentalityRequirement metric
func GetConfidentialityRequirement(s string) ConfidentialityRequirement {
	s = strings.ToUpper(s)
	for k, v := range ConfidentialityRequirementMap {
		if s == v {
			return k
		}
	}
	return ConfidentialityRequirementNotDefined
}

func (cr ConfidentialityRequirement) String() string {
	if s, ok := ConfidentialityRequirementMap[cr]; ok {
		return s
	}
	return ""
}

//Value returns value of AttackVector metric
func (cr ConfidentialityRequirement) Value() float64 {
	if v, ok := ConfidentialityRequirementValueMap[cr]; ok {
		return v
	}
	return 0.0
}

//IsDefined returns false if undefined result value of metric
func (cr ConfidentialityRequirement) IsDefined() bool {
	_, ok := ConfidentialityRequirementValueMap[cr]
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
