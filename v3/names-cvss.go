package v3

import "golang.org/x/text/language"

var cvssNameMap = map[language.Tag]string{
	language.English:  "Common Vulnerability Scoring System (CVSS) v3.0",
	language.Japanese: "共通脆弱性評価システム (CVSS) v3.0",
}

//Name returns string instance name for display
func (c *CVSS) Name(lang language.Tag) string {
	if s, ok := cvssNameMap[lang]; ok {
		return s
	}
	return cvssNameMap[language.English]
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
