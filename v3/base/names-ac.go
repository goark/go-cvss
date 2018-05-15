package base

import "golang.org/x/text/language"

var (
	acNameMap = map[language.Tag]string{
		language.English:  "Attack Complexity",
		language.Japanese: "攻撃条件の複雑さ",
	}
	acValueNameUnknownMap = map[language.Tag]string{
		language.English:  "Unknown",
		language.Japanese: "不明",
	}
	acValueNameHighMap = map[language.Tag]string{
		language.English:  "High",
		language.Japanese: "高",
	}
	acValueNameLowMap = map[language.Tag]string{
		language.English:  "Low",
		language.Japanese: "低",
	}
)

//Title returns string instance name for display
func (ac AttackComplexity) Title(lang language.Tag) string {
	if s, ok := acNameMap[lang]; ok {
		return s
	}
	return acNameMap[language.English]
}

//NameOfValue returns string name of value for display
func (ac AttackComplexity) NameOfValue(lang language.Tag) string {
	var mp map[language.Tag]string
	switch ac {
	case AttackComplexityHigh:
		mp = acValueNameHighMap
	case AttackComplexityLow:
		mp = acValueNameLowMap
	default:
		mp = acValueNameUnknownMap
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
