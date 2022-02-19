package base

import "strings"

//AttackVector is metric type for Base Metrics
type AvailabilityRequirement int

//Constant of AttackVector result
const (
	AvailabilityRequirementNotDefined AvailabilityRequirement = iota
	AvailabilityRequirementLow
	AvailabilityRequirementMedium
	AvailabilityRequirementHigh
)

var AvailabilityRequirementMap = map[AvailabilityRequirement]string{
	AvailabilityRequirementNotDefined: "X",
	AvailabilityRequirementLow:        "L",
	AvailabilityRequirementMedium:     "M",
	AvailabilityRequirementHigh:       "H",
}

var AvailabilityRequirementValueMap = map[AvailabilityRequirement]float64{
	AvailabilityRequirementNotDefined: 1,
	AvailabilityRequirementLow:        0.5,
	AvailabilityRequirementMedium:     1,
	AvailabilityRequirementHigh:       1.5,
}

//GetAvailabilityRequirement returns result of ConfidentalityRequirement metric
func GetAvailabilityRequirement(s string) AvailabilityRequirement {
	s = strings.ToUpper(s)
	for k, v := range AvailabilityRequirementMap {
		if s == v {
			return k
		}
	}
	return AvailabilityRequirementNotDefined
}

func (ar AvailabilityRequirement) String() string {
	if s, ok := AvailabilityRequirementMap[ar]; ok {
		return s
	}
	return ""
}

//Value returns value of AttackVector metric
func (ar AvailabilityRequirement) Value() float64 {
	if v, ok := AvailabilityRequirementValueMap[ar]; ok {
		return v
	}
	return 0.0
}

//IsDefined returns false if undefined result value of metric
func (ar AvailabilityRequirement) IsDefined() bool {
	return ar != AvailabilityRequirementNotDefined
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
