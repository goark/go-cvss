package base

import "golang.org/x/text/language"

var (
	severityNameMap = map[language.Tag]string{
		language.English:  "Severity",
		language.Japanese: "深刻度",
	}
	severityValueNameUnknownMap = map[language.Tag]string{
		language.English:  "Unknown",
		language.Japanese: "不明",
	}
	severityValueNameNoneMap = map[language.Tag]string{
		language.English:  "None",
		language.Japanese: "なし",
	}
	severityValueNameLowMap = map[language.Tag]string{
		language.English:  "Low",
		language.Japanese: "注意",
	}
	severityValueNameMediumMap = map[language.Tag]string{
		language.English:  "Medium",
		language.Japanese: "警告",
	}
	severityValueNameHighMap = map[language.Tag]string{
		language.English:  "High",
		language.Japanese: "重要",
	}
	severityValueNameCriticalMap = map[language.Tag]string{
		language.English:  "Critical",
		language.Japanese: "緊急",
	}
)

//Name returns string instance name for display
func (sv Severity) Name(lang language.Tag) string {
	if s, ok := severityNameMap[lang]; ok {
		return s
	}
	return severityNameMap[language.English]
}

//Name returns string name of value for display
func (sv Severity) NameOfValue(lang language.Tag) string {
	var mp map[language.Tag]string
	switch sv {
	case SeverityNone:
		mp = severityValueNameNoneMap
	case SeverityLow:
		mp = severityValueNameLowMap
	case SeverityMedium:
		mp = severityValueNameMediumMap
	case SeverityHigh:
		mp = severityValueNameHighMap
	case SeverityCritical:
		mp = severityValueNameCriticalMap
	default:
		mp = severityValueNameUnknownMap
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
