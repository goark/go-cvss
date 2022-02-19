package names

import (
	"github.com/spiegel-im-spiegel/go-cvss/v3/metric"
	"golang.org/x/text/language"
)

var (
	msTitleMap = langNameMap{
		language.English:  "Modified Scope",
		language.Japanese: "調整後のスコープ",
	}
	msNamesMap = map[metric.ModifiedScope]langNameMap{
		metric.ModifiedScopeNotDefined: {
			language.English:  "Not Defined",
			language.Japanese: "未評価",
		},
		metric.ModifiedScopeUnchanged: {
			language.English:  "Unchanged",
			language.Japanese: "変更なし",
		},
		metric.ModifiedScopeChanged: {
			language.English:  "Changed",
			language.Japanese: "変更あり",
		},
	}
)

//ModifiedScope returns string instance name for display
func ModifiedScope(lang language.Tag) string {
	return msTitleMap.getNameInLang(lang)
}

//MSValueOf returns string name of value for display
func MSValueOf(ms metric.ModifiedScope, lang language.Tag) string {
	if m, ok := msNamesMap[ms]; ok {
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
