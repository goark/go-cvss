package names

import (
	"github.com/spiegel-im-spiegel/go-cvss/v3/metric"
	"golang.org/x/text/language"
)

var (
	prTitleMap = langNameMap{
		language.English:  "Privileges Required",
		language.Japanese: "必要な特権レベル",
	}
	prNamesMap = map[metric.PrivilegesRequired]langNameMap{
		metric.PrivilegesRequiredNotDefined: langNameMap{
			language.English:  "Not Defined",
			language.Japanese: "未評価",
		},
		metric.PrivilegesRequiredHigh: langNameMap{
			language.English:  "High",
			language.Japanese: "高",
		},
		metric.PrivilegesRequiredLow: langNameMap{
			language.English:  "Low",
			language.Japanese: "低",
		},
		metric.PrivilegesRequiredNone: langNameMap{
			language.English:  "None",
			language.Japanese: "不要",
		},
	}
)

//PrivilegesRequired returns string instance name for display
func PrivilegesRequired(lang language.Tag) string {
	return prTitleMap.getNameInLang(lang)
}

//PRValueOf returns string name of value for display
func PRValueOf(pr metric.PrivilegesRequired, lang language.Tag) string {
	if m, ok := prNamesMap[pr]; ok {
		return m.getNameInLang(lang)
	}
	return unknownValueNameMap.getNameInLang(lang)
}

/* Copyright 2018-2020 Spiegel
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
