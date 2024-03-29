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
		{vector: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/C:L/I:L/A:N", err: cvsserr.ErrNoBaseMetrics, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.0/S:U/AV:N/AC:L/PR:H/UI:N/C:L/I:L/X:N", err: cvsserr.ErrNotSupportMetric, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L/RC:", err: cvsserr.ErrInvalidVector, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L/MC:", err: cvsserr.ErrInvalidVector, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L/:X", err: cvsserr.ErrInvalidVector, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L/:", err: cvsserr.ErrInvalidVector, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:C/C:L/I:H/A:L/E:H/RL:W/RC:R/IR:H/MAV:A/MUI:R/MC:H/MI:L/MA:N/MA:N", err: cvsserr.ErrSameMetric, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:L/IR:M/AR:L/MAV:P/MAC:L/MPR:L/MUI:R/MS:C/MC:H/MI:H/MA:0", err: cvsserr.ErrInvalidValue, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:L/IR:M/AR:L/MAV:P/MAC:L/MPR:L/MUI:R/MS:C/MC:H/MI:H/MA:h", err: cvsserr.ErrInvalidValue, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:L/IR:M/AR:L/MAV:P/MAC:L/MPR:L/MUI:R/MS:C/MC:H/MI:0/MA:H", err: cvsserr.ErrInvalidValue, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:L/IR:M/AR:L/MAV:P/MAC:L/MPR:L/MUI:R/MS:C/MC:H/MI:h/MA:H", err: cvsserr.ErrInvalidValue, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:L/IR:M/AR:L/MAV:P/MAC:L/MPR:L/MUI:R/MS:C/MC:0/MI:H/MA:H", err: cvsserr.ErrInvalidValue, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:L/IR:M/AR:L/MAV:P/MAC:L/MPR:L/MUI:R/MS:C/MC:h/MI:H/MA:H", err: cvsserr.ErrInvalidValue, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:L/IR:M/AR:L/MAV:P/MAC:L/MPR:L/MUI:R/MS:0/MC:H/MI:H/MA:H", err: cvsserr.ErrInvalidValue, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:L/IR:M/AR:L/MAV:P/MAC:L/MPR:L/MUI:R/MS:c/MC:H/MI:H/MA:H", err: cvsserr.ErrInvalidValue, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:L/IR:M/AR:L/MAV:P/MAC:L/MPR:L/MUI:0/MS:C/MC:H/MI:H/MA:H", err: cvsserr.ErrInvalidValue, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:L/IR:M/AR:L/MAV:P/MAC:L/MPR:L/MUI:r/MS:C/MC:H/MI:H/MA:H", err: cvsserr.ErrInvalidValue, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:L/IR:M/AR:L/MAV:P/MAC:L/MPR:0/MUI:R/MS:C/MC:H/MI:H/MA:H", err: cvsserr.ErrInvalidValue, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:L/IR:M/AR:L/MAV:P/MAC:L/MPR:l/MUI:R/MS:C/MC:H/MI:H/MA:H", err: cvsserr.ErrInvalidValue, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:L/IR:M/AR:L/MAV:P/MAC:0/MPR:L/MUI:R/MS:C/MC:H/MI:H/MA:H", err: cvsserr.ErrInvalidValue, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:L/IR:M/AR:L/MAV:P/MAC:l/MPR:L/MUI:R/MS:C/MC:H/MI:H/MA:H", err: cvsserr.ErrInvalidValue, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:L/IR:M/AR:L/MAV:0/MAC:L/MPR:L/MUI:R/MS:C/MC:H/MI:H/MA:H", err: cvsserr.ErrInvalidValue, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:L/IR:M/AR:L/MAV:p/MAC:L/MPR:L/MUI:R/MS:C/MC:H/MI:H/MA:H", err: cvsserr.ErrInvalidValue, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:L/IR:M/AR:0/MAV:P/MAC:L/MPR:L/MUI:R/MS:C/MC:H/MI:H/MA:H", err: cvsserr.ErrInvalidValue, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:L/IR:M/AR:l/MAV:P/MAC:L/MPR:L/MUI:R/MS:C/MC:H/MI:H/MA:H", err: cvsserr.ErrInvalidValue, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:L/IR:0/AR:L/MAV:P/MAC:L/MPR:L/MUI:R/MS:C/MC:H/MI:H/MA:H", err: cvsserr.ErrInvalidValue, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:L/IR:m/AR:L/MAV:P/MAC:L/MPR:L/MUI:R/MS:C/MC:H/MI:H/MA:H", err: cvsserr.ErrInvalidValue, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:0/IR:M/AR:L/MAV:P/MAC:L/MPR:L/MUI:R/MS:C/MC:H/MI:H/MA:H", err: cvsserr.ErrInvalidValue, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:l/IR:M/AR:L/MAV:P/MAC:L/MPR:L/MUI:R/MS:C/MC:H/MI:H/MA:H", err: cvsserr.ErrInvalidValue, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/cr:l/ir:m/ar:l/mav:p/mac:l/mpr:l/mui:r/ms:c/mc:h/mi:h/ma:h", err: cvsserr.ErrNotSupportMetric, score: 0, sav: SeverityNone},
		{vector: "CVSS:3.0/S:U/AV:N/AC:L/PR:H/UI:N/C:L/I:L/A:N", err: nil, score: 3.8, sav: SeverityLow},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:L/IR:M/AR:L/MAV:P/MAC:L/MPR:L/MUI:R/MS:C/MC:H/MI:H/MA:H", err: nil, score: 5.5, sav: SeverityMedium},
		{vector: "CVSS:3.1/S:U/AV:N/AC:L/PR:H/UI:N/C:L/I:L/A:N/E:F", err: nil, score: 3.7, sav: SeverityLow},
		{vector: "CVSS:3.1/S:U/AV:N/AC:L/PR:H/UI:N/C:L/I:L/A:N/E:F/RL:X", err: nil, score: 3.7, sav: SeverityLow},
		{vector: "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N/E:F/RL:W/RC:R", err: nil, score: 5.6, sav: SeverityMedium},
		{vector: "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:H/E:U/RL:T/RC:C/IR:M/MPR:H/MS:C/MC:N/MI:L/MA:H", err: nil, score: 5.5, sav: SeverityMedium},
		{vector: "CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:C/C:L/I:H/A:L/E:H/RL:W/RC:R/IR:H/MAV:A/MUI:R/MC:H/MI:L/MA:N", err: nil, score: 6.4, sav: SeverityMedium},
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N/MS:C", err: nil, score: 6.5, sav: SeverityMedium},
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

func TestEnvironmentalDecodeEncode(t *testing.T) {
	testCases := []struct {
		vector string
		err    error
	}{
		{vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:L/IR:M/AR:L/MAV:P/MAC:L/MPR:L/MUI:R/MS:C/MC:H/MI:H/MA:H", err: nil},
	}

	for _, tc := range testCases {
		m, err := NewEnvironmental().Decode(tc.vector)
		if !errors.Is(err, tc.err) {
			t.Errorf("Decode(%s) = \"%+v\", want \"%v\".", tc.vector, err, tc.err)
		}
		if err == nil {
			v, err := m.Encode()
			if err != nil {
				t.Errorf("Encode() = \"%+v\", want <nil>.", err)
			}
			if v != tc.vector {
				t.Errorf("Encode() = \"%v\", want \"%v\".", v, tc.vector)
			}
			if m.String() != tc.vector {
				t.Errorf("String() = \"%v\", want \"%v\".", m.String(), tc.vector)
			}
		}
	}
}

/* Copyright 2022 thejohnbrown */
/* Contributed by Spiegel, 2023 */
