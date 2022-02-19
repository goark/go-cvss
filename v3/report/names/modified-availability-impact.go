package names

import (
	"github.com/spiegel-im-spiegel/go-cvss/v3/metric"
	"golang.org/x/text/language"
)

var (
	maTitleMap = langNameMap{
		language.English:  "Modified Availability Impact",
		language.Japanese: "調整後の可用性への影響",
	}
	maNamesMap = map[metric.ModifiedAvailabilityImpact]langNameMap{
		metric.ModifiedAvailabilityImpactNotDefined: {
			language.English:  "Not Defined",
			language.Japanese: "未評価",
		},
		metric.ModifiedAvailabilityImpactNone: {
			language.English:  "None",
			language.Japanese: "なし",
		},
		metric.ModifiedAvailabilityImpactLow: {
			language.English:  "Low",
			language.Japanese: "低",
		},
		metric.ModifiedAvailabilityImpactHigh: {
			language.English:  "High",
			language.Japanese: "高",
		},
	}
)

//ModifiedAvailabilityImpact returns string instance name for display
func ModifiedAvailabilityImpact(lang language.Tag) string {
	return maTitleMap.getNameInLang(lang)
}

//MAValueOf returns string name of value for display
func MAValueOf(ma metric.ModifiedAvailabilityImpact, lang language.Tag) string {
	if m, ok := maNamesMap[ma]; ok {
		return m.getNameInLang(lang)
	}
	return unknownValueNameMap.getNameInLang(lang)
}

/* Copyright 2022 Spiegel
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
