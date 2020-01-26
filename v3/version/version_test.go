package version

import "testing"

func TestVersion(t *testing.T) {
	testCases := []struct {
		v string
		n Num
		s string
	}{
		{v: "3.0", n: V3_0, s: "3.0"},
		{v: "3.1", n: V3_1, s: "3.1"},
		{v: "1.0", n: Unknown, s: "unknown"},
		{v: "2.0", n: Unknown, s: "unknown"},
	}
	for _, tc := range testCases {
		n := Get(tc.v)
		if n != tc.n {
			t.Errorf("Version %v = \"%v\", want \"%v\".", tc.v, n, tc.n)
		}
		s := n.String()
		if s != tc.s {
			t.Errorf("Version %v = \"%v\", want \"%v\".", tc.v, s, tc.s)
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
