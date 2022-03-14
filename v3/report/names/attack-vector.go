package names

import (
	"github.com/goark/go-cvss/v3/metric"
	"golang.org/x/text/language"
)

var (
	avTitleMap = langNameMap{
		language.English:  "Attack Vector",
		language.Japanese: "攻撃元区分",
	}
	avNamesMap = map[metric.AttackVector]langNameMap{
		metric.AttackVectorNotDefined: {
			language.English:  "Not Defined",
			language.Japanese: "未評価",
		},
		metric.AttackVectorPhysical: {
			language.English:  "Physical",
			language.Japanese: "物理",
		},
		metric.AttackVectorLocal: {
			language.English:  "Local",
			language.Japanese: "ローカル",
		},
		metric.AttackVectorAdjacent: {
			language.English:  "Adjacent",
			language.Japanese: "隣接",
		},
		metric.AttackVectorNetwork: {
			language.English:  "Network",
			language.Japanese: "ネットワーク",
		},
	}
)

//AttackVector returns string instance name for display
func AttackVector(lang language.Tag) string {
	return avTitleMap.getNameInLang(lang)
}

//AVValueOf returns string name of value for display
func AVValueOf(av metric.AttackVector, lang language.Tag) string {
	if m, ok := avNamesMap[av]; ok {
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
