package names

import (
	"github.com/goark/go-cvss/v3/metric"
	"golang.org/x/text/language"
)

var (
	muiTitleMap = langNameMap{
		language.English:  "Modified User Interaction",
		language.Japanese: "調整後のユーザ関与レベル",
	}
	muiNamesMap = map[metric.ModifiedUserInteraction]langNameMap{
		metric.ModifiedUserInteractionNotDefined: {
			language.English:  "Not Defined",
			language.Japanese: "未評価",
		},
		metric.ModifiedUserInteractionRequired: {
			language.English:  "Required",
			language.Japanese: "要",
		},
		metric.ModifiedUserInteractionNone: {
			language.English:  "None",
			language.Japanese: "不要",
		},
	}
)

//ModifiedUserInteraction returns string instance name for display
func ModifiedUserInteraction(lang language.Tag) string {
	return muiTitleMap.getNameInLang(lang)
}

//MUIValueOf returns string name of value for display
func MUIValueOf(mui metric.ModifiedUserInteraction, lang language.Tag) string {
	if m, ok := muiNamesMap[mui]; ok {
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
