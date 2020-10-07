package names

import "golang.org/x/text/language"

var (
	unknownValueNameMap = langNameMap{
		language.English:  "Unknown",
		language.Japanese: "未定義",
	}
	metricVakueMap = langNameMap{
		language.English:  "Metric Value",
		language.Japanese: "評価値",
	}
)

type langNameMap map[language.Tag]string

func (ln langNameMap) getNameInLang(lang language.Tag) string {
	if s, ok := ln[lang]; ok {
		return s
	}
	if s, ok := ln[language.English]; ok {
		return s
	}
	return ""
}

/* Copyright 2020 Spiegel
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
