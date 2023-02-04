package metric

import (
	"errors"
	"testing"

	"github.com/goark/go-cvss/cvsserr"
)

func TestValidationBase(t *testing.T) {
	testCases := []struct {
		vec string
		err error
	}{
		{vec: "AV:N/AC:H/Au:M/C:C/I:N/A:", err: cvsserr.ErrInvalidVector},
		{vec: "AV:N/AC:H/Au:M/C:C/I:N/:", err: cvsserr.ErrInvalidVector},
		{vec: "AV:N/AC:H/Au:M/C:C/I:N/X:X", err: cvsserr.ErrNotSupportMetric},
		{vec: "AV:N/AC:H/Au:M/C:C/I:N", err: cvsserr.ErrNoBaseMetrics},
		{vec: "AV:N/AC:H/Au:M/C:C/I:N/A:0", err: cvsserr.ErrInvalidValue},
		{vec: "AV:N/AC:H/Au:M/C:C/I:0/A:C", err: cvsserr.ErrInvalidValue},
		{vec: "AV:N/AC:H/Au:M/C:0/I:N/A:C", err: cvsserr.ErrInvalidValue},
		{vec: "AV:N/AC:H/Au:0/C:C/I:N/A:C", err: cvsserr.ErrInvalidValue},
		{vec: "AV:N/AC:0/Au:M/C:C/I:N/A:C", err: cvsserr.ErrInvalidValue},
		{vec: "AV:0/AC:H/Au:M/C:C/I:N/A:C", err: cvsserr.ErrInvalidValue},
		{vec: "AV:N/AC:H/Au:M/C:C/A:C/I:N", err: cvsserr.ErrMisordered},
		{vec: "AV:N/AC:L/Au:N/C:N/I:N/A:C", err: nil},
	}

	for _, tc := range testCases {
		_, err := NewBase().Decode(tc.vec)
		if !errors.Is(err, tc.err) {
			t.Errorf("Decode(%s) = \"%+v\", want \"%v\".", tc.vec, err, tc.err)
		}
	}
}

func TestValidationTemporal(t *testing.T) {
	testCases := []struct {
		vec string
		err error
	}{
		{vec: "AV:N/AC:H/Au:M/C:C/I:N/A:C/E:U/RL:ND/RC:", err: cvsserr.ErrInvalidVector},
		{vec: "AV:N/AC:H/Au:M/C:C/I:N/A:C/E:U/RL:ND/:", err: cvsserr.ErrInvalidVector},
		{vec: "AV:N/AC:H/Au:M/C:C/I:N/A:C/E:U/RL:ND/X:X", err: cvsserr.ErrNotSupportMetric},
		{vec: "AV:N/AC:H/Au:M/C:C/I:N/A:C/E:U/RL:ND/RC:0", err: cvsserr.ErrInvalidValue},
		{vec: "AV:N/AC:H/Au:M/C:C/I:N/A:C/E:U/RL:0/RC:ND", err: cvsserr.ErrInvalidValue},
		{vec: "AV:N/AC:H/Au:M/C:C/I:N/A:C/E:0/RL:ND/RC:ND", err: cvsserr.ErrInvalidValue},
		{vec: "AV:N/AC:H/Au:M/C:C/I:N/A:C/E:U/RL:ND", err: cvsserr.ErrNoTemporalMetrics},
		{vec: "AV:N/AC:L/Au:N/C:N/I:N/E:U/RL:ND/RC:ND", err: cvsserr.ErrNoBaseMetrics},
		{vec: "AV:N/AC:L/Au:N/C:N/A:C/I:N/E:U/RL:ND/RC:ND", err: cvsserr.ErrMisordered},
		{vec: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:U/RC:ND/RL:ND", err: cvsserr.ErrMisordered},
		{vec: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:U/RL:ND/RC:ND", err: nil},
	}

	for _, tc := range testCases {
		_, err := NewTemporal().Decode(tc.vec)
		if !errors.Is(err, tc.err) {
			t.Errorf("Decode(%s) = \"%+v\", want \"%v\".", tc.vec, err, tc.err)
		}
	}
}

func TestValidationEnvironmental(t *testing.T) {
	testCases := []struct {
		vec string
		err error
	}{
		{vec: "AV:N/AC:H/Au:M/C:C/I:N/A:C/E:U/RL:ND/RC:ND/CDP:H/TD:H/CR:M/IR:M/AR:", err: cvsserr.ErrInvalidVector},
		{vec: "AV:N/AC:H/Au:M/C:C/I:N/A:C/E:U/RL:ND/RC:ND/CDP:H/TD:H/CR:M/IR:M/:", err: cvsserr.ErrInvalidVector},
		{vec: "AV:N/AC:H/Au:M/C:C/I:N/A:C/E:U/RL:ND/RC:ND/CDP:H/TD:H/CR:M/IR:M/X:X", err: cvsserr.ErrNotSupportMetric},
		{vec: "AV:N/AC:H/Au:M/C:C/I:N/A:C/E:U/RL:ND/RC:ND/CDP:H/TD:H/CR:M/IR:M/AR:0", err: cvsserr.ErrInvalidValue},
		{vec: "AV:N/AC:H/Au:M/C:C/I:N/A:C/E:U/RL:ND/RC:ND/CDP:H/TD:H/CR:M/IR:0/AR:H", err: cvsserr.ErrInvalidValue},
		{vec: "AV:N/AC:H/Au:M/C:C/I:N/A:C/E:U/RL:ND/RC:ND/CDP:H/TD:H/CR:0/IR:M/AR:H", err: cvsserr.ErrInvalidValue},
		{vec: "AV:N/AC:H/Au:M/C:C/I:N/A:C/E:U/RL:ND/RC:ND/CDP:H/TD:0/CR:M/IR:M/AR:H", err: cvsserr.ErrInvalidValue},
		{vec: "AV:N/AC:H/Au:M/C:C/I:N/A:C/E:U/RL:ND/RC:ND/CDP:0/TD:H/CR:M/IR:M/AR:H", err: cvsserr.ErrInvalidValue},
		{vec: "av:n/ac:l/au:n/c:n/i:n/a:c/e:u/rl:nd/rc:nd/cdp:h/td:h/cr:m/ir:m/ar:h", err: cvsserr.ErrNotSupportMetric},
		{vec: "AV:N/AC:L/AU:N/C:N/I:N/A:C/E:U/RL:ND/RC:ND/CDP:H/TD:H/CR:M/IR:M/AR:H", err: cvsserr.ErrNotSupportMetric},
		{vec: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:U/RL:ND/RC:ND/CDP:H/TD:H/CR:M/IR:M", err: cvsserr.ErrNoEnvironmentalMetrics},
		{vec: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:U/RL:ND/CDP:H/TD:H/CR:M/IR:M/AR:H", err: cvsserr.ErrNoTemporalMetrics},
		{vec: "AV:N/AC:L/Au:N/C:N/I:N/E:U/RL:ND/RC:ND/CDP:H/TD:H/CR:M/IR:M/AR:H", err: cvsserr.ErrNoBaseMetrics},
		{vec: "AV:N/AC:L/Au:N/C:N/A:C/I:N/E:U/RL:ND/RC:ND/CDP:H/TD:H/CR:M/IR:M/AR:H", err: cvsserr.ErrMisordered},
		{vec: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:U/RC:ND/RL:ND/CDP:H/TD:H/CR:M/IR:M/AR:H", err: cvsserr.ErrMisordered},
		{vec: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:U/RL:ND/RC:ND/CDP:H/TD:H/CR:M/AR:H/IR:M", err: cvsserr.ErrMisordered},
		{vec: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:U/RL:ND/RC:ND/CDP:H/TD:H/CR:M/IR:M/AR:H", err: nil},
	}

	for _, tc := range testCases {
		_, err := NewEnvironmental().Decode(tc.vec)
		if !errors.Is(err, tc.err) {
			t.Errorf("Decode(%s) = \"%+v\", want \"%v\".", tc.vec, err, tc.err)
		}
	}
}

func TestBaseScore(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		want   float64
	}{
		{
			name:   "CVE-2002-0392",
			vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C",
			want:   7.8,
		},
		{
			name:   "CVE-2003-0818",
			vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C",
			want:   10.0,
		},
		{
			name:   "CVE-2003-0062",
			vector: "AV:L/AC:H/Au:N/C:C/I:C/A:C",
			want:   6.2,
		},
		// {
		// 	name:   "test",
		// 	vector: "AV:N/AC:H/Au:M/C:C/I:N/A:C/E:U/RL:ND/RC:ND",
		// 	want:   6.2,
		// },
		{
			name:   "test2",
			vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C",
			want:   7.8,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewBase().Decode(tt.vector)
			if err != nil {
				t.Error(err)
			} else {
				if got := m.Score(); got != tt.want {
					t.Errorf("Metrics.Score() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestBaseTemporalScore(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		base   float64
		temp   float64
	}{
		{
			name:   "CVE-2002-0392",
			vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C",
			base:   7.8,
			temp:   6.4,
		},
		{
			name:   "CVE-2003-0818",
			vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C",
			base:   10.0,
			temp:   8.3,
		},
		{
			name:   "CVE-2003-0062",
			vector: "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C",
			base:   6.2,
			temp:   4.9,
		},
		{
			name:   "CVE-2003-0062-baseonly",
			vector: "AV:L/AC:H/Au:N/C:C/I:C/A:C",
			base:   6.2,
			temp:   6.2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewTemporal().Decode(tt.vector)
			if err != nil {
				t.Error(err)
			} else {
				if got := m.Base.Score(); got != tt.base {
					t.Errorf("Metrics.Base.Score() = %v, want %v", got, tt.base)
				}
				if got := m.Score(); got != tt.temp {
					t.Errorf("Metrics.Score() = %v, want %v", got, tt.temp)
				}
				if got := m.String(); tt.vector != got {
					t.Errorf("Metrics.String() = %v, want %v", got, tt.temp)
				}
			}
		})
	}
}

func TestEnvEnvironmentalScore(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		base   float64
		temp   float64
		env    float64
	}{
		{
			name:   "CVE-2002-0392",
			vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:H",
			base:   7.8,
			temp:   6.4,
			env:    9.2,
		},
		{
			name:   "CVE-2003-0818",
			vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:L",
			base:   10.0,
			temp:   8.3,
			env:    9.0,
		},
		{
			name:   "CVE-2003-0062",
			vector: "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:M",
			base:   6.2,
			temp:   4.9,
			env:    7.5,
		},
		{
			name:   "CVE-2003-0062-baseonly",
			vector: "AV:L/AC:H/Au:N/C:C/I:C/A:C",
			base:   6.2,
			temp:   6.2,
			env:    6.2,
		},
		{
			name:   "CVE-2003-0062-temporal",
			vector: "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C",
			base:   6.2,
			temp:   4.9,
			env:    4.9,
		},
		{
			name:   "CVE-2003-0062-skip-temporal",
			vector: "AV:L/AC:H/Au:N/C:C/I:C/A:C/CDP:H/TD:H/CR:M/IR:M/AR:M",
			base:   6.2,
			temp:   6.2,
			env:    8.1,
		},
		{
			name:   "issue-33",
			vector: "AV:A/AC:L/Au:N/C:C/I:C/A:C/CDP:H/TD:H/CR:L/IR:ND/AR:ND",
			base:   8.3,
			temp:   8.3,
			env:    9.0,
		},
		{
			name:   "issue-33b",
			vector: "AV:A/AC:L/Au:N/C:C/I:C/A:C/E:ND/RL:ND/RC:ND/CDP:H/TD:ND/CR:L/IR:ND/AR:ND",
			base:   8.3,
			temp:   8.3,
			env:    9.0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewEnvironmental().Decode(tt.vector)
			if err != nil {
				t.Error(err)
			} else {
				if got := m.Base.Score(); got != tt.base {
					t.Errorf("Metrics.Score() = %v, want %v", got, tt.base)
				}
				if got := m.Temporal.Score(); got != tt.temp {
					t.Errorf("Metrics.TemporalScore() = %v, want %v", got, tt.env)
				}
				if got := m.Score(); got != tt.env {
					t.Errorf("Metrics.EnvironmentalScore() = %v, want %v", got, tt.env)
				}
				if got := m.String(); tt.vector != got {
					t.Errorf("Metrics.String() = %v, want %v", got, tt.vector)
				}
			}

		})
	}
}

func TestEncodeBase(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		outp   string
	}{
		{name: "CVE-2020-7477", vector: "AV:N/AC:L/Au:S/C:N/I:N/A:P", outp: "AV:N/AC:L/Au:S/C:N/I:N/A:P"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewBase().Decode(tt.vector)
			if err != nil {
				t.Error(err)
			} else if m.String() != tt.outp {
				t.Errorf("String() = %v, want %v.", m.String(), tt.outp)
			}
		})
	}
}

func TestTemporalEncode(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		outp   string
	}{
		{name: "CVE-2018-7846-1", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:POC/RL:TF/RC:C", outp: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:POC/RL:TF/RC:C"},
		{name: "CVE-2018-7846-2", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:ND/RL:ND/RC:ND", outp: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:ND/RL:ND/RC:ND"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewTemporal().Decode(tt.vector)
			if err != nil {
				t.Error(err)
			} else if m.String() != tt.outp {
				t.Errorf("String() = %v, want %v.", m.String(), tt.outp)
			}
		})
	}
}

func TestEnvironmentalEncode(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		outp   string
	}{
		{name: "Issue #23-1", vector: "AV:L/AC:M/Au:S/C:N/I:N/A:P/E:POC/RL:TF/RC:C/CDP:N/TD:H/CR:M/IR:M/AR:M", outp: "AV:L/AC:M/Au:S/C:N/I:N/A:P/E:POC/RL:TF/RC:C/CDP:N/TD:H/CR:M/IR:M/AR:M"},
		{name: "Issue #23-2", vector: "AV:L/AC:M/Au:S/C:N/I:N/A:P/E:POC/RL:TF/RC:C/CDP:ND/TD:ND/CR:M/IR:ND/AR:ND", outp: "AV:L/AC:M/Au:S/C:N/I:N/A:P/E:POC/RL:TF/RC:C/CDP:ND/TD:ND/CR:M/IR:ND/AR:ND"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewEnvironmental().Decode(tt.vector)
			if err != nil {
				t.Error(err)
			} else if m.String() != tt.outp {
				t.Errorf("String() = %v, want %v.", m.String(), tt.outp)
			}
		})
	}
}

/* Copyright 2023 Spiegel
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
