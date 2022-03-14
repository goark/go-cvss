package names

import (
	"github.com/goark/go-cvss/v3/metric"
	"golang.org/x/text/language"
)

var (
	aTitleMap = langNameMap{
		language.English:  "Availability Impact",
		language.Japanese: "可用性への影響",
	}
	aNamesMap = map[metric.AvailabilityImpact]langNameMap{
		metric.AvailabilityImpactNotDefined: {
			language.English:  "Not Defined",
			language.Japanese: "未評価",
		},
		metric.AvailabilityImpactNone: {
			language.English:  "None",
			language.Japanese: "なし",
		},
		metric.AvailabilityImpactLow: {
			language.English:  "Low",
			language.Japanese: "低",
		},
		metric.AvailabilityImpactHigh: {
			language.English:  "High",
			language.Japanese: "高",
		},
	}
)

//AvailabilityImpact returns string instance name for display
func AvailabilityImpact(lang language.Tag) string {
	return aTitleMap.getNameInLang(lang)
}

//AValueOf returns string name of value for display
func AValueOf(a metric.AvailabilityImpact, lang language.Tag) string {
	if m, ok := aNamesMap[a]; ok {
		return m.getNameInLang(lang)
	}
	return unknownValueNameMap.getNameInLang(lang)
}

/* Copyright 2018-2022 Spiegel
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
