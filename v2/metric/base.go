package metric

import (
	"fmt"
	"strings"

	"github.com/goark/errs"
	"github.com/goark/go-cvss/cvsserr"
)

const (
	metricAV = "AV"
	metricAC = "AC"
	metricAu = "Au"
	metricC  = "C"
	metricI  = "I"
	metricA  = "A"
)

// Base is Base Metrics for CVSSv2
type Base struct {
	AV    AccessVector
	AC    AccessComplexity
	Au    Authentication
	C     ConfidentialityImpact
	I     IntegrityImpact
	A     AvailabilityImpact
	names map[string]bool
}

// NewMetrics returns Metrics instance
func NewBase() *Base {
	return &Base{
		AV:    AccessVectorUnknown,
		AC:    AccessComplexityUnknown,
		Au:    AuthenticationUnknown,
		C:     ConfidentialityImpactUnknown,
		I:     IntegrityImpactUnknown,
		A:     AvailabilityImpactUnknown,
		names: map[string]bool{},
	}
}

// Decode returns Metrics instance by CVSSv2 vector
func (m *Base) Decode(vector string) (*Base, error) {
	if m == nil {
		m = NewBase()
	}
	values := strings.Split(vector, "/")
	// parse metrics
	var lastErr error
	for _, value := range values {
		if err := m.decodeOne(value); err != nil {
			if !errs.Is(err, cvsserr.ErrNotSupportMetric) {
				return nil, errs.Wrap(err, errs.WithContext("vector", vector))
			}
			lastErr = err
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	enc, err := m.Encode()
	if err != nil {
		return nil, errs.Wrap(err, errs.WithContext("vector", vector))
	}
	if vector != enc {
		return nil, errs.Wrap(cvsserr.ErrMisordered, errs.WithContext("vector", vector))
	}
	return m, nil
}

func (m *Base) decodeOne(str string) error {
	elm := strings.Split(str, ":")
	if len(elm) != 2 || len(elm[0]) == 0 || len(elm[1]) == 0 {
		return errs.Wrap(cvsserr.ErrInvalidVector, errs.WithContext("metric", str))
	}
	name := elm[0]
	if m.names[name] {
		return errs.Wrap(cvsserr.ErrSameMetric, errs.WithContext("metric", str))
	}
	switch name {
	case metricAV: // Access Vector
		m.AV = GetAccessVector(elm[1])
		if m.AV == AccessVectorUnknown {
			return errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", str))
		}
	case metricAC: // Access Complexity
		m.AC = GetAccessComplexity(elm[1])
		if m.AC == AccessComplexityUnknown {
			return errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", str))
		}
	case metricAu: // Authentication
		m.Au = GetAuthentication(elm[1])
		if m.Au == AuthenticationUnknown {
			return errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", str))
		}
	case metricC: // Confidentiality Impact
		m.C = GetConfidentialityImpact(elm[1])
		if m.C == ConfidentialityImpactUnknown {
			return errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", str))
		}
	case metricI: // Integrity Impact
		m.I = GetIntegrityImpact(elm[1])
		if m.I == IntegrityImpactUnknown {
			return errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", str))
		}
	case metricA: // Availability Impact
		m.A = GetAvailabilityImpact(elm[1])
		if m.A == AvailabilityImpactUnknown {
			return errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", str))
		}
	default:
		return errs.Wrap(cvsserr.ErrNotSupportMetric, errs.WithContext("vector", str))
	}
	m.names[name] = true
	return nil
}

// GetError returns error instance if unknown metric
func (m *Base) GetError() error {
	if m == nil {
		return errs.Wrap(cvsserr.ErrNoBaseMetrics)
	}
	switch true {
	case !m.AV.IsUnknown(), !m.AC.IsUnknown(), !m.Au.IsUnknown(), !m.C.IsUnknown(), !m.I.IsUnknown(), !m.A.IsUnknown():
		return errs.Wrap(cvsserr.ErrNoBaseMetrics)
	default:
		return nil
	}
}

// Encode returns CVSSv2 vector string
func (m *Base) Encode() (string, error) {
	if m == nil {
		return "", errs.Wrap(cvsserr.ErrNoBaseMetrics)
	}
	r := []string{}
	if m.names[metricAV] {
		r = append(r, fmt.Sprintf("%s:%v", metricAV, m.AV)) // Access Vector
	}
	if m.names[metricAC] {
		r = append(r, fmt.Sprintf("%s:%v", metricAC, m.AC)) // Access Complexity
	}
	if m.names[metricAu] {
		r = append(r, fmt.Sprintf("%s:%v", metricAu, m.Au)) // Authentication
	}
	if m.names[metricC] {
		r = append(r, fmt.Sprintf("%s:%v", metricC, m.C)) // Confidentiality Impact
	}
	if m.names[metricI] {
		r = append(r, fmt.Sprintf("%s:%v", metricI, m.I)) // Integrity Impact
	}
	if m.names[metricA] {
		r = append(r, fmt.Sprintf("%s:%v", metricA, m.A)) // Availability Impact
	}
	return strings.Join(r, "/"), m.GetError()
}

// String is stringer method.
func (m *Base) String() string {
	s, _ := m.Encode()
	return s
}

// Score returns score of Base metrics
func (m *Base) Score() float64 {
	if err := m.GetError(); err != nil {
		return 0
	}
	impact := roundTo2Decimal(10.41 * (1 - (1-m.C.Value())*(1-m.I.Value())*(1-m.A.Value())))
	return m.score(impact)
}

func (m *Base) score(impact float64) float64 {
	if err := m.GetError(); err != nil {
		return 0
	}
	exploitability := roundTo2Decimal(20 * m.AV.Value() * m.AC.Value() * m.Au.Value())
	fimpact := 1.176
	if impact == 0 {
		fimpact = 0
	}
	return roundTo1Decimal(((0.6 * impact) + (0.4 * exploitability) - 1.5) * fimpact)
}

// GetSeverity returns severity by score of Base metrics
func (m *Base) Severity() Severity {
	return severity(m.Score())
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
