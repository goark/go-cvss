package base

import "strings"

//Authentication is metric type for Base Metrics
type Authentication int

//Constant of Authentication result
const (
	AuthenticationUnknown Authentication = iota
	AuthenticationNone
	AuthenticationSingle
	AuthenticationMultiple
)

var authenticationMap = map[Authentication]string{
	AuthenticationNone:     "N",
	AuthenticationSingle:   "S",
	AuthenticationMultiple: "M",
}

var authenticationValueMap = map[Authentication]float64{
	AuthenticationNone:     0.704,
	AuthenticationSingle:   0.56,
	AuthenticationMultiple: 0.45,
}

//GetAuthentication returns result of Authentication metric
func GetAuthentication(s string) Authentication {
	s = strings.ToUpper(s)
	for k, v := range authenticationMap {
		if s == v {
			return k
		}
	}
	return AuthenticationUnknown
}

func (av Authentication) String() string {
	if s, ok := authenticationMap[av]; ok {
		return s
	}
	return ""
}

//Value returns value of Authentication metric
func (av Authentication) Value() float64 {
	if v, ok := authenticationValueMap[av]; ok {
		return v
	}
	return 0.0
}

//IsDefined returns false if undefined result value of metric
func (av Authentication) IsDefined() bool {
	return av != AuthenticationUnknown
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
