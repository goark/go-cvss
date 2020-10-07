package names

import (
	"github.com/spiegel-im-spiegel/go-cvss/v3/metric"
	"golang.org/x/text/language"
)

var (
	severityTitleMap = langNameMap{
		language.English:  "Severity",
		language.Japanese: "深刻度",
	}
	severityNamesMap = map[metric.Severity]langNameMap{
		metric.SeverityNone: langNameMap{
			language.English:  metric.SeverityNone.String(),
			language.Japanese: "なし",
		},
		metric.SeverityLow: langNameMap{
			language.English:  metric.SeverityLow.String(),
			language.Japanese: "注意",
		},
		metric.SeverityMedium: langNameMap{
			language.English:  metric.SeverityMedium.String(),
			language.Japanese: "警告",
		},
		metric.SeverityHigh: langNameMap{
			language.English:  metric.SeverityHigh.String(),
			language.Japanese: "重要",
		},
		metric.SeverityCritical: langNameMap{
			language.English:  metric.SeverityCritical.String(),
			language.Japanese: "緊急",
		},
	}
)

//Severity returns string of Severity
func Severity(lang language.Tag) string {
	return severityTitleMap.getNameInLang(lang)
}

//SeverityValueOf returns string name of value for display
func SeverityValueOf(sv metric.Severity, lang language.Tag) string {
	if m, ok := severityNamesMap[sv]; ok {
		return m.getNameInLang(lang)
	}
	return unknownValueNameMap.getNameInLang(lang)
}

/* Copyright 2018-2020 Spiegel
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
