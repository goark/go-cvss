package base

import "testing"

func TestConfidentialityImpact(t *testing.T) {
	testCases := []struct {
		input   string
		result  ConfidentialityImpact
		res     string
		value   float64
		defined bool
	}{
		{input: "X", result: ConfidentialityImpactUnknown, res: "", value: 0.0, defined: false},
		{input: "N", result: ConfidentialityImpactNone, res: "N", value: 0.0, defined: true},
		{input: "L", result: ConfidentialityImpactLow, res: "L", value: 0.22, defined: true},
		{input: "H", result: ConfidentialityImpactHigh, res: "H", value: 0.56, defined: true},
	}

	for _, tc := range testCases {
		r := GetConfidentialityImpact(tc.input)
		if r != tc.result {
			t.Errorf("GetConfidentialityImpact(%v) = %v, want %v.", tc.input, r, tc.result)
		}
		str := r.String()
		if str != tc.res {
			t.Errorf("ConfidentialityImpact.String(%v) = \"%v\", want \"%v\".", tc.input, str, tc.res)
		}
		v := r.Value()
		if v != tc.value {
			t.Errorf("ConfidentialityImpact.Value(%v) = %v, want %v.", tc.input, v, tc.value)
		}
		if r.IsDefined() != tc.defined {
			t.Errorf("ConfidentialityImpact.IsDefined(%v) = %v, want %v.", tc.input, r.IsDefined(), tc.defined)
		}
	}
}
