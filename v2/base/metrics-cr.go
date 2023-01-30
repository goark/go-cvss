package base

// ConfidentialityRequirement is metric type for Temporal Metrics
type ConfidentialityRequirement int

// Constant of ConfidentialityRequirement result
const (
	ConfidentialityRequirementInvalid ConfidentialityRequirement = iota
	ConfidentialityRequirementNotDefined
	ConfidentialityRequirementLow
	ConfidentialityRequirementMedium
	ConfidentialityRequirementHigh
)

var confidentialityRequirementMap = map[ConfidentialityRequirement]string{
	ConfidentialityRequirementNotDefined: "ND",
	ConfidentialityRequirementLow:        "L",
	ConfidentialityRequirementMedium:     "M",
	ConfidentialityRequirementHigh:       "H",
}

var confidentialityRequirementValueMap = map[ConfidentialityRequirement]float64{
	ConfidentialityRequirementNotDefined: 1.0,
	ConfidentialityRequirementLow:        0.5,
	ConfidentialityRequirementMedium:     1.0,
	ConfidentialityRequirementHigh:       1.51,
}

// GetConfidentialityRequirement returns result of ConfidentialityRequirement metric
func GetConfidentialityRequirement(s string) ConfidentialityRequirement {
	for k, v := range confidentialityRequirementMap {
		if s == v {
			return k
		}
	}
	return ConfidentialityRequirementInvalid
}

func (cr ConfidentialityRequirement) String() string {
	if s, ok := confidentialityRequirementMap[cr]; ok {
		return s
	}
	return ""
}

// Value returns value of ConfidentialityRequirement metric
func (cr ConfidentialityRequirement) Value() float64 {
	if v, ok := confidentialityRequirementValueMap[cr]; ok {
		return v
	}
	return 0
}

// IsValid returns false if invalid result value of metric
func (cr ConfidentialityRequirement) IsValid() bool {
	return cr != ConfidentialityRequirementInvalid
}

// IsDefined returns false if undefined result value of metric
func (cr ConfidentialityRequirement) IsDefined() bool {
	return cr.IsValid() && cr != ConfidentialityRequirementNotDefined
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
