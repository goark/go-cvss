package names

import (
	"github.com/goark/go-cvss/v3/metric"
	"golang.org/x/text/language"
)

var (
	macTitleMap = langNameMap{
		language.English:  "Modified Attack Complexity",
		language.Japanese: "調整後の攻撃条件の複雑さ",
	}
	macNamesMap = map[metric.ModifiedAttackComplexity]langNameMap{
		metric.ModifiedAttackComplexityNotDefined: {
			language.English:  "Not Defined",
			language.Japanese: "未評価",
		},
		metric.ModifiedAttackComplexityHigh: {
			language.English:  "High",
			language.Japanese: "高",
		},
		metric.ModifiedAttackComplexityLow: {
			language.English:  "Low",
			language.Japanese: "低",
		},
	}
)

//ModifiedAttackComplexity returns string instance name for display
func ModifiedAttackComplexity(lang language.Tag) string {
	return macTitleMap.getNameInLang(lang)
}

//MACValueOf returns string name of value for display
func MACValueOf(mac metric.ModifiedAttackComplexity, lang language.Tag) string {
	if m, ok := macNamesMap[mac]; ok {
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
