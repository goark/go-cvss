package base

import "golang.org/x/text/language"

var (
	iNameMap = map[language.Tag]string{
		language.English:  "Integrity Impact",
		language.Japanese: "完全性への影響",
	}
	iValueNameUnknownMap = map[language.Tag]string{
		language.English:  "Unknown",
		language.Japanese: "不明",
	}
	iValueNameNoneMap = map[language.Tag]string{
		language.English:  "None",
		language.Japanese: "なし",
	}
	iValueNameLowMap = map[language.Tag]string{
		language.English:  "Low",
		language.Japanese: "低",
	}
	iValueNameHighMap = map[language.Tag]string{
		language.English:  "High",
		language.Japanese: "高",
	}
)

//Name returns string instance name for display
func (i IntegrityImpact) Name(lang language.Tag) string {
	if s, ok := iNameMap[lang]; ok {
		return s
	}
	return iNameMap[language.English]
}

//Name returns string name of value for display
func (i IntegrityImpact) NameOfValue(lang language.Tag) string {
	var mp map[language.Tag]string
	switch i {
	case IntegrityImpactNone:
		mp = iValueNameNoneMap
	case IntegrityImpactLow:
		mp = iValueNameLowMap
	case IntegrityImpactHigh:
		mp = iValueNameHighMap
	default:
		mp = iValueNameUnknownMap
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
