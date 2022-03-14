package v3

import (
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/goark/go-cvss/cvsserr"
	"golang.org/x/text/language"
)

func TestImportBaseVector(t *testing.T) {
	testCases := []struct {
		vector string
		err    error
	}{
		{vector: "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: nil},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: nil},
		{vector: "XXX:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvsserr.ErrInvalidVector},
		{vector: "CVSS:2.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvsserr.ErrNotSupportVer},
		{vector: "CVSS:3.1/AV:X/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvsserr.ErrUndefinedMetric},
	}
	for _, tc := range testCases {
		err := New().ImportBaseVector(tc.vector)
		if !errors.Is(err, tc.err) {
			t.Errorf("CVSS.ImportBaseVector(%s) = \"%v\", want \"%v\".", tc.vector, err, tc.err)
		}
	}
}

func TestTitle(t *testing.T) {
	testCases := []struct {
		lang language.Tag
		s    string
	}{
		{lang: language.Und, s: "Common Vulnerability Scoring System (CVSS) v3.1"},
		{lang: language.English, s: "Common Vulnerability Scoring System (CVSS) v3.1"},
		{lang: language.Japanese, s: "共通脆弱性評価システム (CVSS) v3.1"},
	}
	for _, tc := range testCases {
		s := New().Title(tc.lang)
		if s != tc.s {
			t.Errorf("CVSS.Title(%v) = \"%v\", want \"%v\".", tc.lang, s, tc.s)
		}
	}
}

func ExampleCVSS() {
	m := New()
	if err := m.ImportBaseVector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	severity := m.Base.GetSeverity()
	fmt.Printf("%s: %v (%.1f)\n\n", severity.Title(language.English), severity, m.Base.Score())
	if r, err := m.Base.Report(nil, language.English); err != nil { //output with CSV format
		fmt.Fprintln(os.Stderr, err)
	} else {
		_, _ = io.Copy(os.Stdout, r)
	}
	// Output:
	//Severity: Critical (9.9)
	//
	//Base Metrics,Metric Value
	//Attack Vector,Network
	//Attack Complexity,Low
	//Privileges Required,Low
	//User Interaction,None
	//Scope,Changed
	//Confidentiality Impact,High
	//Integrity Impact,High
	//Availability Impact,High
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
