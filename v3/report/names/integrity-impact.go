package names

import (
	"github.com/goark/go-cvss/v3/metric"
	"golang.org/x/text/language"
)

var (
	iTitleMap = langNameMap{
		language.English:  "Integrity Impact",
		language.Japanese: "完全性への影響",
	}
	iNamesMap = map[metric.IntegrityImpact]langNameMap{
		metric.IntegrityImpactNone: {
			language.English:  "None",
			language.Japanese: "なし",
		},
		metric.IntegrityImpactLow: {
			language.English:  "Low",
			language.Japanese: "低",
		},
		metric.IntegrityImpactHigh: {
			language.English:  "High",
			language.Japanese: "高",
		},
	}
)

// IntegrityImpact returns string instance name for display
func IntegrityImpact(lang language.Tag) string {
	return iTitleMap.getNameInLang(lang)
}

// IValueOf returns string name of value for display
func IValueOf(i metric.IntegrityImpact, lang language.Tag) string {
	if m, ok := iNamesMap[i]; ok {
		return m.getNameInLang(lang)
	}
	return unknownValueNameMap.getNameInLang(lang)
}

/* Copyright 2018-2023 Spiegel
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
