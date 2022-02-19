package base

import "strings"

//ModifiedAttackVector is metric type for Base Metrics
type ModifiedAttackVector int

//Constant of ModifiedAttackVector result
const (
	ModifiedAttackVectorNotDefined ModifiedAttackVector = iota
	ModifiedAttackVectorPhysical
	ModifiedAttackVectorLocal
	ModifiedAttackVectorAdjacent
	ModifiedAttackVectorNetwork
)

var ModifiedAttackVectorMap = map[ModifiedAttackVector]string{
	ModifiedAttackVectorNotDefined: "X",
	ModifiedAttackVectorPhysical:   "P",
	ModifiedAttackVectorLocal:      "L",
	ModifiedAttackVectorAdjacent:   "A",
	ModifiedAttackVectorNetwork:    "N",
}

var ModifiedAttackVectorValueMap = map[ModifiedAttackVector]float64{
	ModifiedAttackVectorNotDefined: 0,
	ModifiedAttackVectorPhysical:   0.20,
	ModifiedAttackVectorLocal:      0.55,
	ModifiedAttackVectorAdjacent:   0.62,
	ModifiedAttackVectorNetwork:    0.85,
}

//GetModifiedAttackVector returns result of ModifiedAttackVector metric
func GetModifiedAttackVector(s string) ModifiedAttackVector {
	s = strings.ToUpper(s)
	for k, v := range ModifiedAttackVectorMap {
		if s == v {
			return k
		}
	}
	return ModifiedAttackVectorNotDefined
}

func (mav ModifiedAttackVector) String() string {
	if s, ok := ModifiedAttackVectorMap[mav]; ok {
		return s
	}
	return ""
}

//Value returns value of ModifiedAttackVector metric
func (mav ModifiedAttackVector) Value() float64 {
	if v, ok := ModifiedAttackVectorValueMap[mav]; ok {
		return v
	}
	return 0.0
}

//IsDefined returns false if undefined result value of metric
func (mav ModifiedAttackVector) IsDefined() bool {
	return mav != ModifiedAttackVectorNotDefined
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
