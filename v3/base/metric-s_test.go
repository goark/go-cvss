package base

import "testing"

func TestScope(t *testing.T) {
	testCases := []struct {
		input   string
		result  Scope
		res     string
		defined bool
	}{
		{input: "X", result: ScopeUnknown, res: "", defined: false},
		{input: "U", result: ScopeUnchanged, res: "U", defined: true},
		{input: "C", result: ScopeChanged, res: "C", defined: true},
	}

	for _, tc := range testCases {
		r := GetScope(tc.input)
		if r != tc.result {
			t.Errorf("GetScope(%v) = %v, want %v.", tc.input, r, tc.result)
		}
		str := r.String()
		if str != tc.res {
			t.Errorf("Scope.String(%v) = \"%v\", want \"%v\".", tc.input, str, tc.res)
		}
		if r.IsDefined() != tc.defined {
			t.Errorf("Scope.IsDefined(%v) = %v, want %v.", tc.input, r.IsDefined(), tc.defined)
		}
	}
}
