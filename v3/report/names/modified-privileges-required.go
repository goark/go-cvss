package names

import (
	"github.com/spiegel-im-spiegel/go-cvss/v3/metric"
	"golang.org/x/text/language"
)

var (
	mprTitleMap = langNameMap{
		language.English:  "Modified Privileges Required",
		language.Japanese: "調整後の必要な特権レベル",
	}
	mprNamesMap = map[metric.ModifiedPrivilegesRequired]langNameMap{
		metric.ModifiedPrivilegesRequiredNotDefined: {
			language.English:  "Not Defined",
			language.Japanese: "未評価",
		},
		metric.ModifiedPrivilegesRequiredHigh: {
			language.English:  "High",
			language.Japanese: "高",
		},
		metric.ModifiedPrivilegesRequiredLow: {
			language.English:  "Low",
			language.Japanese: "低",
		},
		metric.ModifiedPrivilegesRequiredNone: {
			language.English:  "None",
			language.Japanese: "不要",
		},
	}
)

//ModifiedPrivilegesRequired returns string instance name for display
func ModifiedPrivilegesRequired(lang language.Tag) string {
	return mprTitleMap.getNameInLang(lang)
}

//MPRValueOf returns string name of value for display
func MPRValueOf(mpr metric.ModifiedPrivilegesRequired, lang language.Tag) string {
	if m, ok := mprNamesMap[mpr]; ok {
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
