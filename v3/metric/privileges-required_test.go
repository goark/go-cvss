package metric

import "testing"

func TestPrivilegesRequired(t *testing.T) {
	testCases := []struct {
		input   string
		result  PrivilegesRequired
		sc      Scope
		res     string
		value   float64
		defined bool
	}{
		{input: "X", result: PrivilegesRequiredUnknown, sc: ScopeUnchanged, res: "", value: 0.0, defined: false},
		{input: "X", result: PrivilegesRequiredUnknown, sc: ScopeChanged, res: "", value: 0.0, defined: false},
		{input: "H", result: PrivilegesRequiredHigh, sc: ScopeUnchanged, res: "H", value: 0.27, defined: true},
		{input: "H", result: PrivilegesRequiredHigh, sc: ScopeChanged, res: "H", value: 0.50, defined: true},
		{input: "L", result: PrivilegesRequiredLow, sc: ScopeUnchanged, res: "L", value: 0.62, defined: true},
		{input: "L", result: PrivilegesRequiredLow, sc: ScopeChanged, res: "L", value: 0.68, defined: true},
		{input: "N", result: PrivilegesRequiredNone, sc: ScopeUnchanged, res: "N", value: 0.85, defined: true},
		{input: "N", result: PrivilegesRequiredNone, sc: ScopeChanged, res: "N", value: 0.85, defined: true},
	}

	for _, tc := range testCases {
		r := GetPrivilegesRequired(tc.input)
		if r != tc.result {
			t.Errorf("GetPrivilegesRequired(%v) = %v, want %v.", tc.input, r, tc.result)
		}
		str := r.String()
		if str != tc.res {
			t.Errorf("PrivilegesRequired.String(%v) = \"%v\", want \"%v\".", tc.input, str, tc.res)
		}
		v := r.Value(tc.sc)
		if v != tc.value {
			t.Errorf("PrivilegesRequired.Value(%v, %v) = %v, want %v.", tc.input, tc.sc, v, tc.value)
		}
		if r.IsDefined() != tc.defined {
			t.Errorf("PrivilegesRequired.IsDefined(%v) = %v, want %v.", tc.input, r.IsDefined(), tc.defined)
		}
	}
}

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
