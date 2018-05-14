package base

import "testing"

func TestIntegrityImpact(t *testing.T) {
	testCases := []struct {
		input   string
		result  IntegrityImpact
		res     string
		value   float64
		defined bool
	}{
		{input: "X", result: IntegrityImpactUnknown, res: "", value: 0.0, defined: false},
		{input: "N", result: IntegrityImpactNone, res: "N", value: 0.0, defined: true},
		{input: "L", result: IntegrityImpactLow, res: "L", value: 0.22, defined: true},
		{input: "H", result: IntegrityImpactHigh, res: "H", value: 0.56, defined: true},
	}

	for _, tc := range testCases {
		r := GetIntegrityImpact(tc.input)
		if r != tc.result {
			t.Errorf("GetIntegrityImpact(%v) = %v, want %v.", tc.input, r, tc.result)
		}
		str := r.String()
		if str != tc.res {
			t.Errorf("IntegrityImpact.String(%v) = \"%v\", want \"%v\".", tc.input, str, tc.res)
		}
		v := r.Value()
		if v != tc.value {
			t.Errorf("IntegrityImpact.Value(%v) = %v, want %v.", tc.input, v, tc.value)
		}
		if r.IsDefined() != tc.defined {
			t.Errorf("IntegrityImpact.IsDefined(%v) = %v, want %v.", tc.input, r.IsDefined(), tc.defined)
		}
	}
}
