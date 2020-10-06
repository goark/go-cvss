package metric

import "testing"

func TestRemediationLevel(t *testing.T) {
	testCases := []struct {
		input   string
		result  RemediationLevel
		res     string
		value   float64
		defined bool
	}{
		{input: "X", result: RemediationLevelNotDefined, res: "X", value: 1.0, defined: true},
		{input: "O", result: RemediationLevelOfficialFix, res: "O", value: 0.95, defined: true},
		{input: "T", result: RemediationLevelTemporaryFix, res: "T", value: 0.96, defined: true},
		{input: "W", result: RemediationLevelWorkaround, res: "W", value: 0.97, defined: true},
		{input: "U", result: RemediationLevelUnavailable, res: "U", value: 1.0, defined: true},
	}

	for _, tc := range testCases {
		r := GetRemediationLevel(tc.input)
		if r != tc.result {
			t.Errorf("GetExploitability(%v) = %v, want %v.", tc.input, r, tc.result)
		}
		str := r.String()
		if str != tc.res {
			t.Errorf("RemediationLevel.String(%v) = \"%v\", want \"%v\".", tc.input, str, tc.res)
		}
		v := r.Value()
		if v != tc.value {
			t.Errorf("RemediationLevel.Value(%v) = %v, want %v.", tc.input, v, tc.value)
		}
		if r.IsDefined() != tc.defined {
			t.Errorf("RemediationLevel.IsDefined(%v) = %v, want %v.", tc.input, r.IsDefined(), tc.defined)
		}
	}
}

/* Copyright 2020 Spiegel
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
