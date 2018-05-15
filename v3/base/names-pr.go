package base

import "golang.org/x/text/language"

var (
	prNameMap = map[language.Tag]string{
		language.English:  "Privileges Required",
		language.Japanese: "必要な特権レベル",
	}
	prValueNameUnknownMap = map[language.Tag]string{
		language.English:  "Unknown",
		language.Japanese: "不明",
	}
	prValueNameHighMap = map[language.Tag]string{
		language.English:  "High",
		language.Japanese: "高",
	}
	prValueNameLowMap = map[language.Tag]string{
		language.English:  "Low",
		language.Japanese: "低",
	}
	prValueNameNoneMap = map[language.Tag]string{
		language.English:  "None",
		language.Japanese: "不要",
	}
)

//Title returns string instance name for display
func (pr PrivilegesRequired) Title(lang language.Tag) string {
	if s, ok := prNameMap[lang]; ok {
		return s
	}
	return prNameMap[language.English]
}

//NameOfValue returns string name of value for display
func (pr PrivilegesRequired) NameOfValue(lang language.Tag) string {
	var mp map[language.Tag]string
	switch pr {
	case PrivilegesRequiredHigh:
		mp = prValueNameHighMap
	case PrivilegesRequiredLow:
		mp = prValueNameLowMap
	case PrivilegesRequiredNone:
		mp = prValueNameNoneMap
	default:
		mp = prValueNameUnknownMap
	}
	if s, ok := mp[lang]; ok {
		return s
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
