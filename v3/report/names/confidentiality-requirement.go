package names

import (
	"github.com/goark/go-cvss/v3/metric"
	"golang.org/x/text/language"
)

var (
	crTitleMap = langNameMap{
		language.English:  "Confidentiality Requirement",
		language.Japanese: "機密性の要求度",
	}
	crNamesMap = map[metric.ConfidentialityRequirement]langNameMap{
		metric.ConfidentialityRequirementNotDefined: {
			language.English:  "Not Defined",
			language.Japanese: "未評価",
		},
		metric.ConfidentialityRequirementLow: {
			language.English:  "Low",
			language.Japanese: "低",
		},
		metric.ConfidentialityRequirementMedium: {
			language.English:  "Medium",
			language.Japanese: "中",
		},
		metric.ConfidentialityRequirementHigh: {
			language.English:  "High",
			language.Japanese: "高",
		},
	}
)

//ConfidentialityRequirement returns string instance name for display
func ConfidentialityRequirement(lang language.Tag) string {
	return crTitleMap.getNameInLang(lang)
}

//CRValueOf returns string name of value for display
func CRValueOf(cr metric.ConfidentialityRequirement, lang language.Tag) string {
	if m, ok := crNamesMap[cr]; ok {
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
