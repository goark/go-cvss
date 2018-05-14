package base

import "golang.org/x/text/language"

var (
	uiNameMap = map[language.Tag]string{
		language.English:  "User Interaction",
		language.Japanese: "ユーザ関与レベル",
	}
	uiValueNameUnknownMap = map[language.Tag]string{
		language.English:  "Unknown",
		language.Japanese: "不明",
	}
	uiValueNameRequiredMap = map[language.Tag]string{
		language.English:  "Required",
		language.Japanese: "要",
	}
	uiValueNameNoneMap = map[language.Tag]string{
		language.English:  "None",
		language.Japanese: "不要",
	}
)

//Name returns string instance name for display
func (ui UserInteraction) Name(lang language.Tag) string {
	if s, ok := uiNameMap[lang]; ok {
		return s
	}
	return uiNameMap[language.English]
}

//Name returns string name of value for display
func (ui UserInteraction) NameOfValue(lang language.Tag) string {
	var mp map[language.Tag]string
	switch ui {
	case UserInteractionRequired:
		mp = uiValueNameRequiredMap
	case UserInteractionNone:
		mp = uiValueNameNoneMap
	default:
		mp = uiValueNameUnknownMap
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
