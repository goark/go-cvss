package base

import "strings"

//AccessVector is metric type for Base Metrics
type AccessVector int

//Constant of AccessVector result
const (
	AccessVectorUnknown AccessVector = iota
	AccessVectorLocal
	AccessVectorAdjacent
	AccessVectorNetwork
)

var accessVectorMap = map[AccessVector]string{
	AccessVectorLocal:    "L",
	AccessVectorAdjacent: "A",
	AccessVectorNetwork:  "N",
}

var accessVectorValueMap = map[AccessVector]float64{
	AccessVectorLocal:    0.395,
	AccessVectorAdjacent: 0.646,
	AccessVectorNetwork:  1,
}

//GetAccessVector returns result of AccessVector metric
func GetAccessVector(s string) AccessVector {
	s = strings.ToUpper(s)
	for k, v := range accessVectorMap {
		if s == v {
			return k
		}
	}
	return AccessVectorUnknown
}

func (av AccessVector) String() string {
	if s, ok := accessVectorMap[av]; ok {
		return s
	}
	return ""
}

//Value returns value of AccessVector metric
func (av AccessVector) Value() float64 {
	if v, ok := accessVectorValueMap[av]; ok {
		return v
	}
	return 0.0
}

//IsDefined returns false if undefined result value of metric
func (av AccessVector) IsDefined() bool {
	return av != AccessVectorUnknown
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
