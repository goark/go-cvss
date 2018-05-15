package v3

import (
	"testing"

	cvss "github.com/spiegel-im-spiegel/go-cvss"
)

func TestImportBaseVector(t *testing.T) {
	testCases := []struct {
		vector string
		err    error
	}{
		{vector: "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: nil},
		{vector: "XXX:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvss.ErrInvalidVector},
		{vector: "CVSS:2.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvss.ErrNotSupportVer},
		{vector: "CVSS:3.0/AV:X/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", err: cvss.ErrUndefinedMetric},
	}
	for _, tc := range testCases {
		err := New().ImportBaseVector(tc.vector)
		if err != tc.err {
			t.Errorf("CVSS.ImportBaseVector(%s) = \"%v\", want \"%v\".", tc.vector, err, tc.err)
		}
	}
}

/* Copyright 2018 Spiegel
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
