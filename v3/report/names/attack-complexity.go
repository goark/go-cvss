package names

import (
	"github.com/goark/go-cvss/v3/metric"
	"golang.org/x/text/language"
)

var (
	acTitleMap = langNameMap{
		language.English:  "Attack Complexity",
		language.Japanese: "攻撃条件の複雑さ",
	}
	acNamesMap = map[metric.AttackComplexity]langNameMap{
		metric.AttackComplexityNotDefined: {
			language.English:  "Not Defined",
			language.Japanese: "未評価",
		},
		metric.AttackComplexityHigh: {
			language.English:  "High",
			language.Japanese: "高",
		},
		metric.AttackComplexityLow: {
			language.English:  "Low",
			language.Japanese: "低",
		},
	}
)

//AttackComplexity returns string instance name for display
func AttackComplexity(lang language.Tag) string {
	return acTitleMap.getNameInLang(lang)
}

//ACValueOf returns string name of value for display
func ACValueOf(ac metric.AttackComplexity, lang language.Tag) string {
	if m, ok := acNamesMap[ac]; ok {
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
