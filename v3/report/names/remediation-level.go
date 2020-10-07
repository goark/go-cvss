package names

import (
	"github.com/spiegel-im-spiegel/go-cvss/v3/metric"
	"golang.org/x/text/language"
)

var (
	rlTitleMap = langNameMap{
		language.English:  "Remediation Level",
		language.Japanese: "利用可能な対策のレベル",
	}
	rlNamesMap = map[metric.RemediationLevel]langNameMap{
		metric.RemediationLevelNotDefined: langNameMap{
			language.English:  "Not Defined",
			language.Japanese: "未評価",
		},
		metric.RemediationLevelOfficialFix: langNameMap{
			language.English:  "Official Fix",
			language.Japanese: "正式",
		},
		metric.RemediationLevelTemporaryFix: langNameMap{
			language.English:  "Temporary Fix",
			language.Japanese: "暫定",
		},
		metric.RemediationLevelWorkaround: langNameMap{
			language.English:  "Workaround",
			language.Japanese: "非公式",
		},
		metric.RemediationLevelUnavailable: langNameMap{
			language.English:  "Unavailable",
			language.Japanese: "なし",
		},
	}
)

//RemediationLevel returns string instance name for display
func RemediationLevel(lang language.Tag) string {
	return rlTitleMap.getNameInLang(lang)
}

//RLValueOf returns string name of value for display
func RLValueOf(rl metric.RemediationLevel, lang language.Tag) string {
	if m, ok := rlNamesMap[rl]; ok {
		return m.getNameInLang(lang)
	}
	return unknownValueNameMap.getNameInLang(lang)
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
