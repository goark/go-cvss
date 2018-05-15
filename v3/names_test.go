package v3

import (
	"testing"

	"golang.org/x/text/language"
)

func TestTitle(t *testing.T) {
	testCases := []struct {
		lang language.Tag
		s    string
	}{
		{lang: language.Und, s: "Common Vulnerability Scoring System (CVSS) v3.0"},
		{lang: language.English, s: "Common Vulnerability Scoring System (CVSS) v3.0"},
		{lang: language.Japanese, s: "共通脆弱性評価システム (CVSS) v3.0"},
	}
	for _, tc := range testCases {
		s := New().Title(tc.lang)
		if s != tc.s {
			t.Errorf("CVSS.Title(%v) = \"%v\", want \"%v\".", tc.lang, s, tc.s)
		}
	}
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
