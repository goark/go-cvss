package cvsserr

import (
	"fmt"

	errors "golang.org/x/xerrors"
)

//Num is error number for CVSS
type Num int

const (
	ErrUndefinedMetric Num = iota + 1
	ErrInvalidVector
	ErrNotSupportVer
)

var errMessage = map[Num]string{
	ErrUndefinedMetric: "undefined metric",
	ErrInvalidVector:   "invalid vector",
	ErrNotSupportVer:   "not support version",
}

func (n Num) Error() string {
	if s, ok := errMessage[n]; ok {
		return s
	}
	return fmt.Sprintf("unknown error (%d)", int(n))
}

func (n Num) Is(target error) bool {
	var t1 *wrapError
	if errors.As(target, &t1) {
		return n == t1.Num
	}
	var t2 Num
	if errors.As(target, &t2) {
		return n == t2
	}
	return false
}

type wrapError struct {
	Num
	frame errors.Frame
}

func New(n Num) error {
	return &wrapError{Num: n, frame: errors.Caller(1)}
}

func (we *wrapError) Format(s fmt.State, v rune) {
	errors.FormatError(we, s, v)
}

func (we *wrapError) FormatError(p errors.Printer) error {
	p.Print(we.Error())
	we.frame.Format(p)
	return nil
}

func (we *wrapError) Is(target error) bool {
	var t1 *wrapError
	if errors.As(target, &t1) {
		return we.Num == t1.Num
	}
	var t2 Num
	if errors.As(target, &t2) {
		return we.Num == t2
	}
	return false
}

/* Copyright 2018,2019 Spiegel
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
