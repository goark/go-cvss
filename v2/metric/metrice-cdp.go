package metric

// CollateralDamagePotential is metric type for Temporal Metrics
type CollateralDamagePotential int

// Constant of CollateralDamagePotential result
const (
	CollateralDamagePotentialInvalid CollateralDamagePotential = iota
	CollateralDamagePotentialNotDefined
	CollateralDamagePotentialNon
	CollateralDamagePotentialLow
	CollateralDamagePotentialLowMedium
	CollateralDamagePotentialMediumHigh
	CollateralDamagePotentialHigh
)

var collateralDamagePotentialMap = map[CollateralDamagePotential]string{
	CollateralDamagePotentialNotDefined: "ND",
	CollateralDamagePotentialNon:        "N",
	CollateralDamagePotentialLow:        "L",
	CollateralDamagePotentialLowMedium:  "LM",
	CollateralDamagePotentialMediumHigh: "MH",
	CollateralDamagePotentialHigh:       "H",
}

var collateralDamagePotentialValueMap = map[CollateralDamagePotential]float64{
	CollateralDamagePotentialNotDefined: 0,
	CollateralDamagePotentialNon:        0,
	CollateralDamagePotentialLow:        0.1,
	CollateralDamagePotentialLowMedium:  0.3,
	CollateralDamagePotentialMediumHigh: 0.4,
	CollateralDamagePotentialHigh:       0.5,
}

// GetCollateralDamagePotential returns result of CollateralDamagePotential metric
func GetCollateralDamagePotential(s string) CollateralDamagePotential {
	for k, v := range collateralDamagePotentialMap {
		if s == v {
			return k
		}
	}
	return CollateralDamagePotentialInvalid
}

func (cdp CollateralDamagePotential) String() string {
	if s, ok := collateralDamagePotentialMap[cdp]; ok {
		return s
	}
	return ""
}

// Value returns value of CollateralDamagePotential metric
func (cdp CollateralDamagePotential) Value() float64 {
	if v, ok := collateralDamagePotentialValueMap[cdp]; ok {
		return v
	}
	return 0
}

// IsValid returns false if invalid result value of metric
func (cdp CollateralDamagePotential) IsValid() bool {
	return cdp != CollateralDamagePotentialInvalid
}

// IsDefined returns false if undefined result value of metric
func (cdp CollateralDamagePotential) IsDefined() bool {
	return cdp.IsValid() && cdp != CollateralDamagePotentialNotDefined
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
