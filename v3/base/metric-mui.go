package base

import "strings"

//ModifiedUserInteraction is metric type for Base Metrics
type ModifiedUserInteraction int

//Constant of ModifiedUserInteraction result
const (
	ModifiedUserInteractionNotDefined ModifiedUserInteraction = iota
	ModifiedUserInteractionRequired
	ModifiedUserInteractionNone
)

var ModifiedUserInteractionMap = map[ModifiedUserInteraction]string{
	ModifiedUserInteractionNotDefined: "X",
	ModifiedUserInteractionRequired:   "R",
	ModifiedUserInteractionNone:       "N",
}

var ModifiedUserInteractionValueMap = map[ModifiedUserInteraction]float64{
	ModifiedUserInteractionRequired: 0.62,
	ModifiedUserInteractionNone:     0.85,
}

//GetModifiedUserInteraction returns result of ModifiedUserInteraction metric
func GetModifiedUserInteraction(s string) ModifiedUserInteraction {
	s = strings.ToUpper(s)
	for k, v := range ModifiedUserInteractionMap {
		if s == v {
			return k
		}
	}
	return ModifiedUserInteractionNotDefined
}

func (mui ModifiedUserInteraction) String() string {
	if s, ok := ModifiedUserInteractionMap[mui]; ok {
		return s
	}
	return ""
}

//Value returns value of ModifiedUserInteraction metric
func (mui ModifiedUserInteraction) Value() float64 {
	if v, ok := ModifiedUserInteractionValueMap[mui]; ok {
		return v
	}
	return 0.0
}

//IsDefined returns false if undefined result value of metric
func (mui ModifiedUserInteraction) IsDefined() bool {
	return mui != ModifiedUserInteractionNotDefined
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
