package metric

import "testing"

func TestReportConfidence(t *testing.T) {
	testCases := []struct {
		input   string
		result  ReportConfidence
		res     string
		value   float64
		defined bool
	}{
		{input: "X", result: ReportConfidenceNotDefined, res: "X", value: 1.0, defined: true},
		{input: "U", result: ReportConfidenceUnknown, res: "U", value: 0.92, defined: true},
		{input: "R", result: ReportConfidenceReasonable, res: "R", value: 0.96, defined: true},
		{input: "C", result: ReportConfidenceConfirmed, res: "C", value: 1.0, defined: true},
	}

	for _, tc := range testCases {
		r := GetReportConfidence(tc.input)
		if r != tc.result {
			t.Errorf("GetReportConfidence(%v) = %v, want %v.", tc.input, r, tc.result)
		}
		str := r.String()
		if str != tc.res {
			t.Errorf("ReportConfidence.String(%v) = \"%v\", want \"%v\".", tc.input, str, tc.res)
		}
		v := r.Value()
		if v != tc.value {
			t.Errorf("ReportConfidence.Value(%v) = %v, want %v.", tc.input, v, tc.value)
		}
		if r.IsDefined() != tc.defined {
			t.Errorf("ReportConfidence.IsDefined(%v) = %v, want %v.", tc.input, r.IsDefined(), tc.defined)
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
