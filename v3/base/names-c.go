package base

import "golang.org/x/text/language"

var (
	cNameMap = map[language.Tag]string{
		language.English:  "Confidentiality Impact",
		language.Japanese: "機密性への影響",
	}
	cValueNameUnknownMap = map[language.Tag]string{
		language.English:  "Unknown",
		language.Japanese: "不明",
	}
	cValueNameNoneMap = map[language.Tag]string{
		language.English:  "None",
		language.Japanese: "なし",
	}
	cValueNameLowMap = map[language.Tag]string{
		language.English:  "Low",
		language.Japanese: "低",
	}
	cValueNameHighMap = map[language.Tag]string{
		language.English:  "High",
		language.Japanese: "高",
	}
)

//Title returns string instance name for display
func (c ConfidentialityImpact) Title(lang language.Tag) string {
	if s, ok := cNameMap[lang]; ok {
		return s
	}
	return cNameMap[language.English]
}

//NameOfValue returns string name of value for display
func (c ConfidentialityImpact) NameOfValue(lang language.Tag) string {
	var mp map[language.Tag]string
	switch c {
	case ConfidentialityImpactNone:
		mp = cValueNameNoneMap
	case ConfidentialityImpactLow:
		mp = cValueNameLowMap
	case ConfidentialityImpactHigh:
		mp = cValueNameHighMap
	default:
		mp = cValueNameUnknownMap
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
