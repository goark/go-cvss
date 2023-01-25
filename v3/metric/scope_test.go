package metric

import "testing"

func TestScope(t *testing.T) {
	testCases := []struct {
		input   string
		result  Scope
		res     string
		defined bool
	}{
		{input: "Z", result: ScopeUnknown, res: "", defined: false},
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
		if r.IsUnknown() == tc.defined {
			t.Errorf("Scope.IsDefined(%v) = %v, want %v.", tc.input, r.IsUnknown(), tc.defined)
		}
	}
}

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
