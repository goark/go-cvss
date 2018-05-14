package base

import "testing"

func TestUserInteraction(t *testing.T) {
	testCases := []struct {
		input   string
		result  UserInteraction
		res     string
		value   float64
		defined bool
	}{
		{input: "X", result: UserInteractionUnknown, res: "", value: 0.0, defined: false},
		{input: "R", result: UserInteractionRequired, res: "R", value: 0.62, defined: true},
		{input: "N", result: UserInteractionNone, res: "N", value: 0.85, defined: true},
	}

	for _, tc := range testCases {
		r := GetUserInteraction(tc.input)
		if r != tc.result {
			t.Errorf("GetUserInteraction(%v) = %v, want %v.", tc.input, r, tc.result)
		}
		str := r.String()
		if str != tc.res {
			t.Errorf("UserInteraction.String(%v) = \"%v\", want \"%v\".", tc.input, str, tc.res)
		}
		v := r.Value()
		if v != tc.value {
			t.Errorf("UserInteraction.Value(%v) = %v, want %v.", tc.input, v, tc.value)
		}
		if r.IsDefined() != tc.defined {
			t.Errorf("UserInteraction.IsDefined(%v) = %v, want %v.", tc.input, r.IsDefined(), tc.defined)
		}
	}
}
