package base

import (
	"errors"
	"testing"

	"github.com/goark/go-cvss/cvsserr"
)

func TestDecodeError(t *testing.T) {
	testCases := []struct {
		vector string
		err    error
	}{
		{vector: "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: nil},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: nil},
		{vector: "XXX:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvsserr.ErrInvalidVector},
		{vector: "CVSS:2.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvsserr.ErrNotSupportVer},
		{vector: "CVSS:3.1", err: cvsserr.ErrInvalidVector},
		{vector: "CVSS3.1/AV:X/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvsserr.ErrInvalidVector},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A-N", err: cvsserr.ErrInvalidVector},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/X:N", err: cvsserr.ErrInvalidVector},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:X", err: cvsserr.ErrUndefinedMetric},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:X/A:N", err: cvsserr.ErrUndefinedMetric},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:X/I:N/A:N", err: cvsserr.ErrUndefinedMetric},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:X/C:N/I:N/A:N", err: cvsserr.ErrUndefinedMetric},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:X/S:U/C:N/I:N/A:N", err: cvsserr.ErrUndefinedMetric},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:X/UI:R/S:U/C:N/I:N/A:N", err: cvsserr.ErrUndefinedMetric},
		{vector: "CVSS:3.1/AV:P/AC:X/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvsserr.ErrUndefinedMetric},
		{vector: "CVSS:3.1/AV:X/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvsserr.ErrUndefinedMetric},
	}

	for _, tc := range testCases {
		if _, err := Decode(tc.vector); !errors.Is(err, tc.err) {
			t.Errorf("Decode(%s) = \"%+v\", want \"%v\".", tc.vector, err, tc.err)
		}
	}
}

func TestDecodeEncode(t *testing.T) {
	testCases := []struct {
		vector string
		err    error
	}{
		{vector: "CVSS:3.0/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X", err: cvsserr.ErrUndefinedMetric},
		{vector: "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: nil},
		{vector: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L", err: nil},
		{vector: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", err: nil},
		{vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", err: nil},
	}

	for _, tc := range testCases {
		m, err := Decode(tc.vector)
		if !errors.Is(err, tc.err) {
			t.Errorf("Decode(%s) = \"%+v\", want \"%v\".", tc.vector, err, tc.err)
		}
		v, err := m.Encode()
		if !errors.Is(err, tc.err) {
			t.Errorf("Encode() = \"%+v\", want \"%v\".", err, tc.err)
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
		{vector: "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:X", score: 0.0, severity: SeverityNone}, //error
		//CVSSv3.0
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
		//CVSSv3.1
		{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", score: 0.0, severity: SeverityNone},     //Zero metrics
		{vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", score: 7.5, severity: SeverityHigh},     //CVE-2015-8252
		{vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", score: 6.1, severity: SeverityMedium},   //CVE-2013-1937
		{vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", score: 6.4, severity: SeverityMedium},   //CVE-2013-0375
		{vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", score: 3.1, severity: SeverityLow},      //CVE-2014-3566
		{vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", score: 9.9, severity: SeverityCritical}, //CVE-2012-1516
		{vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", score: 8.8, severity: SeverityHigh},     //CVE-2012-0384
		{vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", score: 7.8, severity: SeverityHigh},     //CVE-2015-1098
		{vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", score: 7.5, severity: SeverityHigh},     //CVE-2014-0160
		{vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 9.8, severity: SeverityCritical}, //CVE-2014-6271
		{vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N", score: 6.8, severity: SeverityMedium},   //CVE-2008-1447
		{vector: "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 6.8, severity: SeverityMedium},   //CVE-2014-2005
		{vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N", score: 5.8, severity: SeverityMedium},   //CVE-2010-0467
		{vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N", score: 5.8, severity: SeverityMedium},   //CVE-2012-1342
		{vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", score: 5.4, severity: SeverityMedium},   //CVE-2014-9253
		{vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", score: 7.8, severity: SeverityHigh},     //CVE-2009-0658
		{vector: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 8.8, severity: SeverityHigh},     //CVE-2011-1265
		{vector: "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", score: 4.6, severity: SeverityMedium},   //CVE-2014-2019
		{vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", score: 8.8, severity: SeverityHigh},     //CVE-2015-0970
		{vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", score: 7.4, severity: SeverityHigh},     //CVE-2014-0224
		{vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", score: 9.6, severity: SeverityCritical}, //CVE-2012-5376
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

func TestTemporalScore(t *testing.T) {
	testCases := []struct {
		vector string
		score  float64
	}{
		{vector: "CVSS:3.1/S:U/AV:N/AC:L/PR:H/UI:N/C:L/I:L/A:N/E:F/RL:X", score: 3.7},
		{vector: "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N/E:F/RL:W/RC:R", score: 5.6},
	}

	for _, tc := range testCases {
		m, _ := Decode(tc.vector)
		score := m.TemporalScore()
		if score != tc.score {
			t.Errorf("Score(%s) = %v, want %v.", tc.vector, score, tc.score)
		}
	}
}

/* Contributed by Florent Viel, 2020 */
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
