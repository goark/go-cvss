package names

import (
	"github.com/spiegel-im-spiegel/go-cvss/v3/metric"
	"golang.org/x/text/language"
)

var (
	rcTitleMap = langNameMap{
		language.English:  "Report Confidence",
		language.Japanese: "脆弱性情報の信頼性",
	}
	rcNamesMap = map[metric.ReportConfidence]langNameMap{
		metric.ReportConfidenceNotDefined: {
			language.English:  "Not Defined",
			language.Japanese: "未評価",
		},
		metric.ReportConfidenceUnknown: {
			language.English:  "Unknown",
			language.Japanese: "未確認",
		},
		metric.ReportConfidenceReasonable: {
			language.English:  "Reasonable",
			language.Japanese: "未確証",
		},
		metric.ReportConfidenceConfirmed: {
			language.English:  "Confirmed",
			language.Japanese: "確認済",
		},
	}
)

//ReportConfidence returns string instance name for display
func ReportConfidence(lang language.Tag) string {
	return rcTitleMap.getNameInLang(lang)
}

//RCValueOf returns string name of value for display
func RCValueOf(rc metric.ReportConfidence, lang language.Tag) string {
	if m, ok := rcNamesMap[rc]; ok {
		return m.getNameInLang(lang)
	}
	return unknownValueNameMap.getNameInLang(lang)
}

/* Copyright 2020-2022 Spiegel
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
