package cvsserr

import (
	"fmt"
	"os"
	"testing"

	"golang.org/x/xerrors"
)

func TestNumError(t *testing.T) {
	testCases := []struct {
		err error
		str string
	}{
		{err: ErrUndefinedMetric, str: "undefined metric"},
		{err: ErrInvalidVector, str: "invalid vector"},
		{err: ErrNotSupportVer, str: "not support version"},
		{err: Num(4), str: "unknown error (4)"},
	}

	for _, tc := range testCases {
		errStr := tc.err.Error()
		if errStr != tc.str {
			t.Errorf("\"%v\" != \"%v\"", errStr, tc.str)
		}
		fmt.Printf("Info(TestNumError): %+v\n", tc.err)
	}
}

func TestWrapError(t *testing.T) {
	testCases := []struct {
		err error
		str string
	}{
		{err: New(ErrUndefinedMetric), str: "undefined metric"},
		{err: New(ErrInvalidVector), str: "invalid vector"},
		{err: New(ErrNotSupportVer), str: "not support version"},
		{err: New(Num(4)), str: "unknown error (4)"},
	}

	for _, tc := range testCases {
		errStr := tc.err.Error()
		if errStr != tc.str {
			t.Errorf("\"%v\" != \"%v\"", errStr, tc.str)
		}
		fmt.Printf("Info(TestWrapError): %+v\n", tc.err)
	}
}

func TestErrorEquality(t *testing.T) {
	testCases := []struct {
		err1 error
		err2 error
		res  bool
	}{
		{err1: New(ErrUndefinedMetric), err2: ErrUndefinedMetric, res: true},
		{err1: New(ErrInvalidVector), err2: ErrInvalidVector, res: true},
		{err1: New(ErrNotSupportVer), err2: ErrNotSupportVer, res: true},
		{err1: New(ErrUndefinedMetric), err2: New(ErrUndefinedMetric), res: true},
		{err1: New(ErrInvalidVector), err2: New(ErrInvalidVector), res: true},
		{err1: New(ErrNotSupportVer), err2: New(ErrNotSupportVer), res: true},
		{err1: New(ErrUndefinedMetric), err2: nil, res: false},
		{err1: New(ErrInvalidVector), err2: nil, res: false},
		{err1: New(ErrNotSupportVer), err2: nil, res: false},
		{err1: New(ErrUndefinedMetric), err2: os.ErrInvalid, res: false},
		{err1: New(ErrInvalidVector), err2: os.ErrInvalid, res: false},
		{err1: New(ErrNotSupportVer), err2: os.ErrInvalid, res: false},
		{err1: ErrUndefinedMetric, err2: New(ErrUndefinedMetric), res: true},
		{err1: ErrInvalidVector, err2: New(ErrInvalidVector), res: true},
		{err1: ErrNotSupportVer, err2: New(ErrNotSupportVer), res: true},
		{err1: ErrUndefinedMetric, err2: ErrUndefinedMetric, res: true},
		{err1: ErrInvalidVector, err2: ErrInvalidVector, res: true},
		{err1: ErrNotSupportVer, err2: ErrNotSupportVer, res: true},
		{err1: ErrUndefinedMetric, err2: nil, res: false},
		{err1: ErrInvalidVector, err2: nil, res: false},
		{err1: ErrNotSupportVer, err2: nil, res: false},
		{err1: ErrUndefinedMetric, err2: os.ErrInvalid, res: false},
		{err1: ErrInvalidVector, err2: os.ErrInvalid, res: false},
		{err1: ErrNotSupportVer, err2: os.ErrInvalid, res: false},
	}

	for _, tc := range testCases {
		res := xerrors.Is(tc.err1, tc.err2)
		if res != tc.res {
			t.Errorf("\"%v\" == \"%v\" ? %v, want %v", tc.err1, tc.err2, res, tc.res)
		}
	}
}

/* Copyright 2019 Spiegel
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
