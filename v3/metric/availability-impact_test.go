package metric

import "testing"

func TestAvailabilityImpact(t *testing.T) {
	testCases := []struct {
		input   string
		result  AvailabilityImpact
		res     string
		value   float64
		defined bool
	}{
		{input: "X", result: AvailabilityImpactUnknown, res: "", value: 0.0, defined: false},
		{input: "N", result: AvailabilityImpactNone, res: "N", value: 0.0, defined: true},
		{input: "L", result: AvailabilityImpactLow, res: "L", value: 0.22, defined: true},
		{input: "H", result: AvailabilityImpactHigh, res: "H", value: 0.56, defined: true},
	}

	for _, tc := range testCases {
		r := GetAvailabilityImpact(tc.input)
		if r != tc.result {
			t.Errorf("GetAvailabilityImpact(%v) = %v, want %v.", tc.input, r, tc.result)
		}
		str := r.String()
		if str != tc.res {
			t.Errorf("AvailabilityImpact.String(%v) = \"%v\", want \"%v\".", tc.input, str, tc.res)
		}
		v := r.Value()
		if v != tc.value {
			t.Errorf("AvailabilityImpact.Value(%v) = %v, want %v.", tc.input, v, tc.value)
		}
		if r.IsDefined() != tc.defined {
			t.Errorf("AvailabilityImpact.IsDefined(%v) = %v, want %v.", tc.input, r.IsDefined(), tc.defined)
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
