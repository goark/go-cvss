package metric

import (
	"errors"
	"testing"

	"github.com/goark/go-cvss/cvsserr"
)

func TestVersion(t *testing.T) {
	testCases := []struct {
		v string
		e error
		n Version
		s string
	}{
		{v: "CVSS", e: cvsserr.ErrInvalidVector, n: VUnknown, s: "unknown"},
		{v: "3.0", e: cvsserr.ErrInvalidVector, n: VUnknown, s: "unknown"},
		{v: "CV:SS:3.0", e: cvsserr.ErrInvalidVector, n: VUnknown, s: "unknown"},
		{v: "CVSSv3:3.0", e: cvsserr.ErrInvalidVector, n: VUnknown, s: "unknown"},
		{v: "CVSS:3.0", e: nil, n: V3_0, s: "3.0"},
		{v: "CVSS:3.1", e: nil, n: V3_1, s: "3.1"},
		{v: "CVSS:1.0", e: nil, n: VUnknown, s: "unknown"},
		{v: "CVSS:2.0", e: nil, n: VUnknown, s: "unknown"},
	}
	for _, tc := range testCases {
		n, err := GetVersion(tc.v)
		if !errors.Is(err, tc.e) {
			t.Errorf("Version %v is \"%v\", want nil.", tc.v, err)
		} else {
			if n != tc.n {
				t.Errorf("Version %v = \"%v\", want \"%v\".", tc.v, n, tc.n)
			}
			s := n.String()
			if s != tc.s {
				t.Errorf("Version %v = \"%v\", want \"%v\".", tc.v, s, tc.s)
			}
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
