package base

// AvailabilityRequirement is metric type for Temporal Metrics
type AvailabilityRequirement int

// Constant of AvailabilityRequirement result
const (
	AvailabilityRequirementInvalid AvailabilityRequirement = iota
	AvailabilityRequirementNotDefined
	AvailabilityRequirementLow
	AvailabilityRequirementMedium
	AvailabilityRequirementHigh
)

var availabilityRequirementMap = map[AvailabilityRequirement]string{
	AvailabilityRequirementNotDefined: "ND",
	AvailabilityRequirementLow:        "L",
	AvailabilityRequirementMedium:     "M",
	AvailabilityRequirementHigh:       "H",
}

var availabilityRequirementValueMap = map[AvailabilityRequirement]float64{
	AvailabilityRequirementNotDefined: 1.0,
	AvailabilityRequirementLow:        0.5,
	AvailabilityRequirementMedium:     1.0,
	AvailabilityRequirementHigh:       1.51,
}

// GetAvailabilityRequirement returns result of AvailabilityRequirement metric
func GetAvailabilityRequirement(s string) AvailabilityRequirement {
	for k, v := range availabilityRequirementMap {
		if s == v {
			return k
		}
	}
	return AvailabilityRequirementInvalid
}

func (ar AvailabilityRequirement) String() string {
	if s, ok := availabilityRequirementMap[ar]; ok {
		return s
	}
	return ""
}

// Value returns value of AvailabilityRequirement metric
func (ar AvailabilityRequirement) Value() float64 {
	if v, ok := availabilityRequirementValueMap[ar]; ok {
		return v
	}
	return 0
}

// IsValid returns false if invalid result value of metric
func (ar AvailabilityRequirement) IsValid() bool {
	return ar != AvailabilityRequirementInvalid
}

// IsDefined returns false if undefined result value of metric
func (ar AvailabilityRequirement) IsDefined() bool {
	return ar.IsValid() && ar != AvailabilityRequirementNotDefined
}

/* Copyright 2023 Spiegel
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
