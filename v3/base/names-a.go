package base

import "golang.org/x/text/language"

var (
	aNameMap = map[language.Tag]string{
		language.English:  "Availability Impact",
		language.Japanese: "可用性への影響",
	}
	aValueNameUnknownMap = map[language.Tag]string{
		language.English:  "Unknown",
		language.Japanese: "不明",
	}
	aValueNameNoneMap = map[language.Tag]string{
		language.English:  "None",
		language.Japanese: "なし",
	}
	aValueNameLowMap = map[language.Tag]string{
		language.English:  "Low",
		language.Japanese: "低",
	}
	aValueNameHighMap = map[language.Tag]string{
		language.English:  "High",
		language.Japanese: "高",
	}
)

//Name returns string instance name for display
func (a AvailabilityImpact) Name(lang language.Tag) string {
	if s, ok := aNameMap[lang]; ok {
		return s
	}
	return aNameMap[language.English]
}

//Name returns string name of value for display
func (a AvailabilityImpact) NameOfValue(lang language.Tag) string {
	var mp map[language.Tag]string
	switch a {
	case AvailabilityImpactNone:
		mp = aValueNameNoneMap
	case AvailabilityImpactLow:
		mp = aValueNameLowMap
	case AvailabilityImpactHigh:
		mp = aValueNameHighMap
	default:
		mp = aValueNameUnknownMap
	}
	if s, ok := mp[lang]; ok {
		return s
	}
	return mp[language.English]
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
