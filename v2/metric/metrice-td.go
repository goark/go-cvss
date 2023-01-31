package metric

// TargetDistribution is metric type for Temporal Metrics
type TargetDistribution int

// Constant of TargetDistribution result
const (
	TargetDistributionInvalid TargetDistribution = iota
	TargetDistributionNotDefined
	TargetDistributionNon
	TargetDistributionLow
	TargetDistributionMedium
	TargetDistributionHigh
)

var targetDistributionMap = map[TargetDistribution]string{
	TargetDistributionNotDefined: "ND",
	TargetDistributionNon:        "N",
	TargetDistributionLow:        "L",
	TargetDistributionMedium:     "M",
	TargetDistributionHigh:       "H",
}

var targetDistributionValueMap = map[TargetDistribution]float64{
	TargetDistributionNotDefined: 1.00,
	TargetDistributionNon:        0,
	TargetDistributionLow:        0.25,
	TargetDistributionMedium:     0.75,
	TargetDistributionHigh:       1.00,
}

// GetTargetDistribution returns result of TargetDistribution metric
func GetTargetDistribution(s string) TargetDistribution {
	for k, v := range targetDistributionMap {
		if s == v {
			return k
		}
	}
	return TargetDistributionInvalid
}

func (td TargetDistribution) String() string {
	if s, ok := targetDistributionMap[td]; ok {
		return s
	}
	return ""
}

// Value returns value of TargetDistribution metric
func (td TargetDistribution) Value() float64 {
	if v, ok := targetDistributionValueMap[td]; ok {
		return v
	}
	return 0
}

// IsValid returns false if invalid result value of metric
func (td TargetDistribution) IsValid() bool {
	return td != TargetDistributionInvalid
}

// IsDefined returns false if undefined result value of metric
func (td TargetDistribution) IsDefined() bool {
	return td.IsValid() && td != TargetDistributionNotDefined
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
