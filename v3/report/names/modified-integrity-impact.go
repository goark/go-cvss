package names

import (
	"github.com/goark/go-cvss/v3/metric"
	"golang.org/x/text/language"
)

var (
	miTitleMap = langNameMap{
		language.English:  "Modified Integrity Impact",
		language.Japanese: "調整後の完全性への影響",
	}
	miNamesMap = map[metric.ModifiedIntegrityImpact]langNameMap{
		metric.ModifiedIntegrityImpactNotDefined: {
			language.English:  "Not Defined",
			language.Japanese: "未評価",
		},
		metric.ModifiedIntegrityImpactNone: {
			language.English:  "None",
			language.Japanese: "なし",
		},
		metric.ModifiedIntegrityImpactLow: {
			language.English:  "Low",
			language.Japanese: "低",
		},
		metric.ModifiedIntegrityImpactHigh: {
			language.English:  "High",
			language.Japanese: "高",
		},
	}
)

//ModifiedIntegrityImpact returns string instance name for display
func ModifiedIntegrityImpact(lang language.Tag) string {
	return miTitleMap.getNameInLang(lang)
}

//MIValueOf returns string name of value for display
func MIValueOf(i metric.ModifiedIntegrityImpact, lang language.Tag) string {
	if m, ok := miNamesMap[i]; ok {
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
