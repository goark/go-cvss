package metric

import (
	"errors"
	"testing"

	"github.com/goark/go-cvss/cvsserr"
)

func TestEnvironmentalScore(t *testing.T) {
	testCases := []struct {
		vector string
		err    error
		score  float64
		sav    Severity
	}{
		{vector: "XXXX:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:L/IR:M/AR:L/MAV:P/MAC:L/MPR:L/MUI:R/MS:C/MC:H/MI:H/MA:H", err: cvsserr.ErrInvalidVector, score: 0, sav: SeverityNone},
		{vector: "CVSS:1.0/S:U/AV:N/AC:L/PR:H/UI:N/C:L/I:L/A:N", err: cvsserr.ErrNotSupportVer, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/C:L/I:L/A:N", err: cvsserr.ErrInvalidVector, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.0/S:U/AV:N/AC:L/PR:H/UI:N/C:L/I:L/X:N", err: cvsserr.ErrNotSupportMetric, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L/RC:", err: cvsserr.ErrInvalidVector, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L/MC:", err: cvsserr.ErrInvalidVector, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L/:X", err: cvsserr.ErrInvalidVector, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L/:", err: cvsserr.ErrInvalidVector, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.0/S:U/AV:N/AC:L/PR:H/UI:N/C:L/I:L/A:N", err: nil, score: 3.8, sav: SeverityLow},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:L/IR:M/AR:L/MAV:P/MAC:L/MPR:L/MUI:R/MS:C/MC:H/MI:H/MA:H", err: nil, score: 5.5, sav: SeverityMedium},
		{vector: "CVSS:3.1/S:U/AV:N/AC:L/PR:H/UI:N/C:L/I:L/A:N/E:F", err: nil, score: 3.7, sav: SeverityLow},
		{vector: "CVSS:3.1/S:U/AV:N/AC:L/PR:H/UI:N/C:L/I:L/A:N/E:F/RL:X", err: nil, score: 3.7, sav: SeverityLow},
		{vector: "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N/E:F/RL:W/RC:R", err: nil, score: 5.6, sav: SeverityMedium},
		{vector: "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:H/E:U/RL:T/RC:C/IR:M/MPR:H/MS:C/MC:N/MI:L/MA:H", err: nil, score: 5.5, sav: SeverityMedium},
		{vector: "CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:C/C:L/I:H/A:L/E:H/RL:W/RC:R/IR:H/MAV:A/MUI:R/MC:H/MI:L/MA:N", err: nil, score: 6.4, sav: SeverityMedium},
	}

	for _, tc := range testCases {
		e, err := NewEnvironmental().Decode(tc.vector)
		if !errors.Is(err, tc.err) {
			t.Errorf("Decode(%s) = \"%+v\", want \"%v\".", tc.vector, err, tc.err)
		}
		if err == nil {
			score := e.Score()
			if score != tc.score {
				t.Errorf("Score(%s) = %v, want %v.", tc.vector, score, tc.score)
			}
			sav := e.Severity()
			if sav != tc.sav {
				t.Errorf("Severity(%s) = %v, want %v.", tc.vector, sav, tc.sav)
			}

		}
	}
}

/* Copyright 2022 thejohnbrown */
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
