package base

import "golang.org/x/text/language"

var baseNameMap = map[language.Tag]string{
	language.English:  "Base Metrics",
	language.Japanese: "基本評価基準",
}
var baseVakueMap = map[language.Tag]string{
	language.English:  "Metric Value",
	language.Japanese: "評価値",
}

//Title returns string instance name for display
func (m *Metrics) Title(lang language.Tag) string {
	if s, ok := baseNameMap[lang]; ok {
		return s
	}
	return baseNameMap[language.English]
}

//NameOfvalue returns string instance name for display
func (m *Metrics) NameOfvalue(lang language.Tag) string {
	if s, ok := baseVakueMap[lang]; ok {
		return s
	}
	return baseVakueMap[language.English]
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
