package names

import (
	"github.com/spiegel-im-spiegel/go-cvss/v3/metric"
	"golang.org/x/text/language"
)

var (
	irTitleMap = langNameMap{
		language.English:  "Integrity Requirement",
		language.Japanese: "完全性の要求度",
	}
	irNamesMap = map[metric.IntegrityRequirement]langNameMap{
		metric.IntegrityRequirementNotDefined: {
			language.English:  "Not Defined",
			language.Japanese: "未評価",
		},
		metric.IntegrityRequirementLow: {
			language.English:  "Low",
			language.Japanese: "低",
		},
		metric.IntegrityRequirementMedium: {
			language.English:  "Medium",
			language.Japanese: "中",
		},
		metric.IntegrityRequirementHigh: {
			language.English:  "High",
			language.Japanese: "高",
		},
	}
)

//IntegrityRequirement returns string instance name for display
func IntegrityRequirement(lang language.Tag) string {
	return irTitleMap.getNameInLang(lang)
}

//IRValueOf returns string name of value for display
func IRValueOf(ir metric.IntegrityRequirement, lang language.Tag) string {
	if m, ok := irNamesMap[ir]; ok {
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
