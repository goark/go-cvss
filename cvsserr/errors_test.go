package cvsserr

import (
	"fmt"
	"testing"
)

func TestNumError(t *testing.T) {
	testCases := []struct {
		err error
		str string
	}{
		{err: ErrNullPointer, str: "Null reference instance"},
		{err: ErrUndefinedMetric, str: "undefined metric"},
		{err: ErrInvalidVector, str: "invalid vector"},
		{err: ErrNotSupportVer, str: "not support version"},
		{err: ErrNotSupportMetric, str: "not support metric"},
		{err: ErrInvalidTemplate, str: "invalid templete string"},
		{err: ErrSameMetric, str: "exist same metric"},
		{err: ErrInvalidValue, str: "invalid value of metric"},
		{err: Num(9), str: "unknown error (9)"},
	}

	for _, tc := range testCases {
		errStr := tc.err.Error()
		if errStr != tc.str {
			t.Errorf("\"%v\" != \"%v\"", errStr, tc.str)
		}
		fmt.Printf("Info(TestNumError): %+v\n", tc.err)
	}
}

/* Copyright 2019-2023 Spiegel
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
