package metric

// IntegrityRequirement is metric type for Temporal Metrics
type IntegrityRequirement int

// Constant of IntegrityRequirement result
const (
	IntegrityRequirementInvalid IntegrityRequirement = iota
	IntegrityRequirementNotDefined
	IntegrityRequirementLow
	IntegrityRequirementMedium
	IntegrityRequirementHigh
)

var integrityRequirementMap = map[IntegrityRequirement]string{
	IntegrityRequirementNotDefined: "ND",
	IntegrityRequirementLow:        "L",
	IntegrityRequirementMedium:     "M",
	IntegrityRequirementHigh:       "H",
}

var integrityRequirementValueMap = map[IntegrityRequirement]float64{
	IntegrityRequirementNotDefined: 1.0,
	IntegrityRequirementLow:        0.5,
	IntegrityRequirementMedium:     1.0,
	IntegrityRequirementHigh:       1.51,
}

// GetIntegrityRequirement returns result of IntegrityRequirement metric
func GetIntegrityRequirement(s string) IntegrityRequirement {
	for k, v := range integrityRequirementMap {
		if s == v {
			return k
		}
	}
	return IntegrityRequirementInvalid
}

func (ir IntegrityRequirement) String() string {
	if s, ok := integrityRequirementMap[ir]; ok {
		return s
	}
	return ""
}

// Value returns value of IntegrityRequirement metric
func (ir IntegrityRequirement) Value() float64 {
	if v, ok := integrityRequirementValueMap[ir]; ok {
		return v
	}
	return 0
}

// IsValid returns false if invalid result value of metric
func (ir IntegrityRequirement) IsValid() bool {
	return ir != IntegrityRequirementInvalid
}

// IsDefined returns false if undefined result value of metric
func (ir IntegrityRequirement) IsDefined() bool {
	return ir.IsValid() && ir != IntegrityRequirementNotDefined
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
