package metric

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
		{vector: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:0/A:H", err: cvsserr.ErrInvalidValue},
		{vector: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/A:H", err: cvsserr.ErrSameMetric},
		{vector: "CVSS:2.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvsserr.ErrNotSupportVer},
		{vector: "CVSS:3.1", err: cvsserr.ErrNoBaseMetrics},
		{vector: "CVSS3.1/AV:X/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvsserr.ErrInvalidVector},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A-N", err: cvsserr.ErrInvalidVector},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:", err: cvsserr.ErrInvalidVector},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/:N", err: cvsserr.ErrInvalidVector},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/:", err: cvsserr.ErrInvalidVector},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/X:N", err: cvsserr.ErrNotSupportMetric},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:X", err: cvsserr.ErrInvalidValue},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:n", err: cvsserr.ErrInvalidValue},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:X/A:N", err: cvsserr.ErrInvalidValue},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:n/A:N", err: cvsserr.ErrInvalidValue},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:X/I:N/A:N", err: cvsserr.ErrInvalidValue},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:n/I:N/A:N", err: cvsserr.ErrInvalidValue},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:X/C:N/I:N/A:N", err: cvsserr.ErrInvalidValue},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:u/C:N/I:N/A:N", err: cvsserr.ErrInvalidValue},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:X/S:U/C:N/I:N/A:N", err: cvsserr.ErrInvalidValue},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:r/S:U/C:N/I:N/A:N", err: cvsserr.ErrInvalidValue},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:X/UI:R/S:U/C:N/I:N/A:N", err: cvsserr.ErrInvalidValue},
		{vector: "CVSS:3.1/AV:P/AC:H/PR:h/UI:R/S:U/C:N/I:N/A:N", err: cvsserr.ErrInvalidValue},
		{vector: "CVSS:3.1/AV:P/AC:X/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvsserr.ErrInvalidValue},
		{vector: "CVSS:3.1/AV:P/AC:h/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvsserr.ErrInvalidValue},
		{vector: "CVSS:3.1/AV:X/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvsserr.ErrInvalidValue},
		{vector: "CVSS:3.1/AV:p/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvsserr.ErrInvalidValue},
		{vector: "CVSS:3.0/av:p/ac:h/pr:h/ui:r/s:u/c:n/i:n/a:n", err: cvsserr.ErrNotSupportMetric},
		{vector: "cvss:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvsserr.ErrInvalidVector},
	}

	for _, tc := range testCases {
		if _, err := (*Base)(nil).Decode(tc.vector); !errors.Is(err, tc.err) {
			t.Errorf("Decode(%s) = \"%+v\", want \"%v\".", tc.vector, err, tc.err)
		}
	}
}

func TestDecodeEncode(t *testing.T) {
	testCases := []struct {
		vector string
		err    error
	}{
		{vector: "CVSS:3.0/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X", err: cvsserr.ErrInvalidValue},
		{vector: "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: nil},
		{vector: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L", err: nil},
		{vector: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", err: nil},
		{vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", err: nil},
	}

	for _, tc := range testCases {
		m, err := NewBase().Decode(tc.vector)
		if !errors.Is(err, tc.err) {
			t.Errorf("Decode(%s) = \"%+v\", want \"%v\".", tc.vector, err, tc.err)
		}
		if err == nil {
			v, err := m.Encode()
			if err != nil {
				t.Errorf("Encode() = \"%+v\", want <nil>.", err)
			} else {
				if v != tc.vector {
					t.Errorf("Encode() = \"%v\", want \"%v\".", v, tc.vector)
				}
				if m.String() != tc.vector {
					t.Errorf("String() = \"%v\", want \"%v\".", m.String(), tc.vector)
				}
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

		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N", score: 6.5, severity: SeverityMedium}, //Issue #18
	}

	for _, tc := range testCases {
		m, err := NewBase().Decode(tc.vector)
		if err != nil {
			t.Errorf("Decode(%v) is %v, want <nil>.", tc.vector, err)
		} else {
			score := m.Score()
			if got := m.String(); got != tc.vector {
				t.Errorf("String() = %v, want %v.", got, tc.vector)
			}
			if score != tc.score {
				t.Errorf("Score(%s) = %v, want %v.", tc.vector, score, tc.score)
			}
			severity := m.Severity()
			if severity.String() != tc.severity.String() {
				t.Errorf("Score(%s) = %v, want %v.", tc.vector, severity, tc.severity)
			}
		}
	}
}

/* Contributed by Florent Viel, 2020 */
/* Copyright 2023 Spiegel
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
