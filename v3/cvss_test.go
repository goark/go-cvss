package v3

import (
	"fmt"
	"io"
	"os"
	"testing"

	cvss "github.com/spiegel-im-spiegel/go-cvss"
	"golang.org/x/text/language"
)

func TestImportBaseVector(t *testing.T) {
	testCases := []struct {
		vector string
		err    error
	}{
		{vector: "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: nil},
		{vector: "XXX:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvss.ErrInvalidVector},
		{vector: "CVSS:2.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvss.ErrNotSupportVer},
		{vector: "CVSS:3.0/AV:X/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvss.ErrUndefinedMetric},
	}
	for _, tc := range testCases {
		err := New().ImportBaseVector(tc.vector)
		if err != tc.err {
			t.Errorf("CVSS.ImportBaseVector(%s) = \"%v\", want \"%v\".", tc.vector, err, tc.err)
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
		io.Copy(os.Stdout, r)
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
