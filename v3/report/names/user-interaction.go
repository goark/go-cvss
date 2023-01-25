package names

import (
	"github.com/goark/go-cvss/v3/metric"
	"golang.org/x/text/language"
)

var (
	uiTitleMap = langNameMap{
		language.English:  "User Interaction",
		language.Japanese: "ユーザ関与レベル",
	}
	uiNamesMap = map[metric.UserInteraction]langNameMap{
		metric.UserInteractionRequired: {
			language.English:  "Required",
			language.Japanese: "要",
		},
		metric.UserInteractionNone: {
			language.English:  "None",
			language.Japanese: "不要",
		},
	}
)

// UserInteraction returns string instance name for display
func UserInteraction(lang language.Tag) string {
	return uiTitleMap.getNameInLang(lang)
}

// UIValueOf returns string name of value for display
func UIValueOf(ui metric.UserInteraction, lang language.Tag) string {
	if m, ok := uiNamesMap[ui]; ok {
		return m.getNameInLang(lang)
	}
	return unknownValueNameMap.getNameInLang(lang)
}

/* Copyright 2018-2023 Spiegel
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
