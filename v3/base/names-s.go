package base

import "golang.org/x/text/language"

var (
	sNameMap = map[language.Tag]string{
		language.English:  "Scope",
		language.Japanese: "スコープ",
	}
	sValueNameUnknownMap = map[language.Tag]string{
		language.English:  "Unknown",
		language.Japanese: "不明",
	}
	sValueNameUnchangedMap = map[language.Tag]string{
		language.English:  "Unchanged",
		language.Japanese: "変更なし",
	}
	sValueNameChangedMap = map[language.Tag]string{
		language.English:  "Changed",
		language.Japanese: "変更あり",
	}
)

//Name returns string instance name for display
func (s Scope) Name(lang language.Tag) string {
	if str, ok := sNameMap[lang]; ok {
		return str
	}
	return sNameMap[language.English]
}

//Name returns string name of value for display
func (s Scope) NameOfValue(lang language.Tag) string {
	var mp map[language.Tag]string
	switch s {
	case ScopeUnchanged:
		mp = sValueNameUnchangedMap
	case ScopeChanged:
		mp = sValueNameChangedMap
	default:
		mp = sValueNameUnknownMap
	}
	if str, ok := mp[lang]; ok {
		return str
	}
	return mp[language.English]
}

/* Copyright 2018 Spiegel
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
