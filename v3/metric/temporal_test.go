package metric

import (
	"errors"
	"testing"

	"github.com/goark/go-cvss/cvsserr"
)

func TestTemporalScore(t *testing.T) {
	testCases := []struct {
		vector string
		err    error
		score  float64
		sav    Severity
	}{
		{vector: "XXXX:1.0/S:U/AV:N/AC:L/PR:H/UI:N/C:L/I:L/A:N", err: cvsserr.ErrInvalidVector, score: 0, sav: SeverityNone},
		{vector: "CVSS:1.0/S:U/AV:N/AC:L/PR:H/UI:N/C:L/I:L/A:N", err: cvsserr.ErrNotSupportVer, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/C:L/I:L/A:N", err: cvsserr.ErrInvalidVector, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.0/S:U/AV:N/AC:L/PR:H/UI:N/C:L/I:L/X:N", err: cvsserr.ErrNotSupportMetric, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.0/S:U/AV:N/AC:L/PR:H/UI:N/C:L/I:L/:X", err: cvsserr.ErrInvalidVector, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.0/S:U/AV:N/AC:L/PR:H/UI:N/C:L/I:L/:", err: cvsserr.ErrInvalidVector, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.0/S:U/AV:N/AC:L/PR:H/UI:N/C:L/I:L/A:N", err: nil, score: 3.8, sav: SeverityLow},
		{vector: "CVSS:3.1/S:U/AV:N/AC:L/PR:H/UI:N/C:L/I:L/A:N", err: nil, score: 3.8, sav: SeverityLow},
		{vector: "CVSS:3.1/S:U/AV:N/AC:L/PR:H/UI:N/C:L/I:L/A:N/E:F", err: nil, score: 3.7, sav: SeverityLow},
		{vector: "CVSS:3.1/S:U/AV:N/AC:L/PR:H/UI:N/C:L/I:L/A:N/E:F/RL:X", err: nil, score: 3.7, sav: SeverityLow},
		{vector: "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N/E:F/RL:W/RC:R", err: nil, score: 5.6, sav: SeverityMedium},
	}

	for _, tc := range testCases {
		m, err := NewTemporal().Decode(tc.vector)
		if !errors.Is(err, tc.err) {
			t.Errorf("Decode(%s) = \"%+v\", want \"%v\".", tc.vector, err, tc.err)
		}
		score := m.Score()
		if score != tc.score {
			t.Errorf("Score(%s) = %v, want %v.", tc.vector, score, tc.score)
		}
		sav := m.Severity()
		if sav != tc.sav {
			t.Errorf("Severity(%s) = %v, want %v.", tc.vector, sav, tc.sav)
		}
	}
}

/* Contributed by Florent Viel, 2020 */
/* Copyright 2018-2023 Spiegel
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
