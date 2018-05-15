package base

import (
	"fmt"
	"testing"

	cvss "github.com/spiegel-im-spiegel/go-cvss"
)

func TestDecodeError(t *testing.T) {
	testCases := []struct {
		vector string
		err    error
	}{
		{vector: "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: nil},
		{vector: "XXX:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvss.ErrInvalidVector},
		{vector: "CVSS:2.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvss.ErrNotSupportVer},
		{vector: "CVSS:3.0", err: cvss.ErrInvalidVector},
		{vector: "CVSS3.0/AV:X/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvss.ErrInvalidVector},
		{vector: "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A-N", err: cvss.ErrInvalidVector},
		{vector: "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/X:N", err: cvss.ErrInvalidVector},
		{vector: "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:X", err: cvss.ErrUndefinedMetric},
		{vector: "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:X/A:N", err: cvss.ErrUndefinedMetric},
		{vector: "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:X/I:N/A:N", err: cvss.ErrUndefinedMetric},
		{vector: "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:X/C:N/I:N/A:N", err: cvss.ErrUndefinedMetric},
		{vector: "CVSS:3.0/AV:P/AC:H/PR:H/UI:X/S:U/C:N/I:N/A:N", err: cvss.ErrUndefinedMetric},
		{vector: "CVSS:3.0/AV:P/AC:H/PR:X/UI:R/S:U/C:N/I:N/A:N", err: cvss.ErrUndefinedMetric},
		{vector: "CVSS:3.0/AV:P/AC:X/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvss.ErrUndefinedMetric},
		{vector: "CVSS:3.0/AV:X/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvss.ErrUndefinedMetric},
	}

	for _, tc := range testCases {
		_, err := Decode(tc.vector)
		if err != tc.err {
			t.Errorf("NewMetrics(%s) = \"%v\", want \"%v\".", tc.vector, err, tc.err)
		}
	}
}

func TestDecodeEncode(t *testing.T) {
	testCases := []struct {
		vector string
		err    error
	}{
		{vector: "CVSS:3.0/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X", err: cvss.ErrUndefinedMetric},
		{vector: "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: nil},
		{vector: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L", err: nil},
		{vector: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", err: nil},
		{vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", err: nil},
	}

	for _, tc := range testCases {
		m, err := Decode(tc.vector)
		if err != tc.err {
			t.Errorf("Decode(%s) = \"%v\", want \"%v\".", tc.vector, err, tc.err)
		}
		v, err := m.Encode()
		if err != tc.err {
			t.Errorf("Encode() = \"%v\", want \"%v\".", err, tc.err)
		}
		if err == nil {
			if v != tc.vector {
				t.Errorf("Encode() = \"%v\", want \"%v\".", v, tc.vector)
			}
		}
	}
}

func TestScore(t *testing.T) {
	testCases := []struct {
		vector   string
		score    float64
		severity Severity
	}{
		{vector: "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:X", score: 0.0, severity: SeverityNone},     //error
		{vector: "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", score: 0.0, severity: SeverityNone},     //Zero metrics
		{vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", score: 7.5, severity: SeverityHigh},     //CVE-2015-8252
		{vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", score: 6.1, severity: SeverityMedium},   //CVE-2013-1937
		{vector: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", score: 6.4, severity: SeverityMedium},   //CVE-2013-0375
		{vector: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", score: 3.1, severity: SeverityLow},      //CVE-2014-3566
		{vector: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", score: 9.9, severity: SeverityCritical}, //CVE-2012-1516
		{vector: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", score: 8.8, severity: SeverityHigh},     //CVE-2012-0384
		{vector: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", score: 7.8, severity: SeverityHigh},     //CVE-2015-1098
		{vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", score: 7.5, severity: SeverityHigh},     //CVE-2014-0160
		{vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 9.8, severity: SeverityCritical}, //CVE-2014-6271
		{vector: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N", score: 6.8, severity: SeverityMedium},   //CVE-2008-1447
		{vector: "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 6.8, severity: SeverityMedium},   //CVE-2014-2005
		{vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N", score: 5.8, severity: SeverityMedium},   //CVE-2010-0467
		{vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N", score: 5.8, severity: SeverityMedium},   //CVE-2012-1342
		{vector: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", score: 5.4, severity: SeverityMedium},   //CVE-2014-9253
		{vector: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", score: 7.8, severity: SeverityHigh},     //CVE-2009-0658
		{vector: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 8.8, severity: SeverityHigh},     //CVE-2011-1265
		{vector: "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", score: 4.6, severity: SeverityMedium},   //CVE-2014-2019
		{vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", score: 8.8, severity: SeverityHigh},     //CVE-2015-0970
		{vector: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", score: 7.4, severity: SeverityHigh},     //CVE-2014-0224
		{vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", score: 9.6, severity: SeverityCritical}, //CVE-2012-5376
	}

	for _, tc := range testCases {
		m, _ := Decode(tc.vector)
		score := m.Score()
		if score != tc.score {
			t.Errorf("Score(%s) = %v, want %v.", tc.vector, score, tc.score)
		}
		severity := m.GetSeverity()
		if severity.String() != tc.severity.String() {
			t.Errorf("Score(%s) = %v, want %v.", tc.vector, severity, tc.severity)
		}
	}
}

func ExampleMetrics() {
	m, err := Decode("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") //CVE-2015-8252
	if err != nil {
		return
	}
	fmt.Println("Score =", m.Score())
	fmt.Println("Severity =", m.GetSeverity())
	//Output
	//Score = 7.5
	//Severity = High
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
