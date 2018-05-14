package base

import "testing"

func TestAttackComplexity(t *testing.T) {
	testCases := []struct {
		input   string
		result  AttackComplexity
		res     string
		value   float64
		defined bool
	}{
		{input: "X", result: AttackComplexityUnknown, res: "", value: 0.0, defined: false},
		{input: "H", result: AttackComplexityHigh, res: "H", value: 0.44, defined: true},
		{input: "L", result: AttackComplexityLow, res: "L", value: 0.77, defined: true},
	}

	for _, tc := range testCases {
		r := GetAttackComplexity(tc.input)
		if r != tc.result {
			t.Errorf("GetAttackComplexity(%v) = %v, want %v.", tc.input, r, tc.result)
		}
		str := r.String()
		if str != tc.res {
			t.Errorf("AttackComplexity.String(%v) = \"%v\", want \"%v\".", tc.input, str, tc.res)
		}
		v := r.Value()
		if v != tc.value {
			t.Errorf("AttackComplexity.Value(%v) = %v, want %v.", tc.input, v, tc.value)
		}
		if r.IsDefined() != tc.defined {
			t.Errorf("AttackComplexity.IsDefined(%v) = %v, want %v.", tc.input, r.IsDefined(), tc.defined)
		}
	}
}
