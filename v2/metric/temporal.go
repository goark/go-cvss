package metric

import (
	"fmt"
	"strings"

	"github.com/goark/errs"
	"github.com/goark/go-cvss/cvsserr"
)

const (
	metricE  = "E"
	metricRL = "RL"
	metricRC = "RC"
)

// Temporal is Temporal Metrics for CVSSv2
type Temporal struct {
	*Base
	E     Exploitability
	RL    RemediationLevel
	RC    ReportConfidence
	names map[string]bool
}

// NewTemporal returns Temporal Metrics instance
func NewTemporal() *Temporal {
	return &Temporal{
		Base:  NewBase(),
		E:     ExploitabilityInvalid,
		RL:    RemediationLevelInvalid,
		RC:    ReportConfidenceInvalid,
		names: map[string]bool{},
	}
}

// Decode returns Metrics instance by CVSSv2 vector
func (m *Temporal) Decode(vector string) (*Temporal, error) {
	if m == nil {
		m = NewTemporal()
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
		return m, lastErr
	}
	enc, err := m.Encode()
	if err != nil {
		return m, errs.Wrap(err, errs.WithContext("vector", vector))
	}
	if vector != enc {
		return m, errs.Wrap(cvsserr.ErrMisordered, errs.WithContext("vector", vector))
	}
	return m, nil
}

func (m *Temporal) decodeOne(str string) error {
	if err := m.Base.decodeOne(str); err != nil {
		if !errs.Is(err, cvsserr.ErrNotSupportMetric) {
			return errs.Wrap(err, errs.WithContext("metric", str))
		}
	} else {
		return nil
	}
	elm := strings.Split(str, ":")
	if len(elm) != 2 || len(elm[0]) == 0 || len(elm[1]) == 0 {
		return errs.Wrap(cvsserr.ErrInvalidVector, errs.WithContext("metric", str))
	}
	name := elm[0]
	if m.names[name] {
		return errs.Wrap(cvsserr.ErrSameMetric, errs.WithContext("metric", str))
	}
	switch name {
	case metricE: // Exploitability
		m.E = GetExploitability(elm[1])
		if m.E == ExploitabilityInvalid {
			return errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", str))
		}
	case metricRL: // RemediationLevel
		m.RL = GetRemediationLevel(elm[1])
		if m.RL == RemediationLevelInvalid {
			return errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", str))
		}
	case metricRC: // RemediationLevel
		m.RC = GetReportConfidence(elm[1])
		if m.RC == ReportConfidenceInvalid {
			return errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", str))
		}
	default:
		return errs.Wrap(cvsserr.ErrNotSupportMetric, errs.WithContext("vector", str))
	}
	m.names[name] = true
	return nil
}

// GetError returns error instance if undefined metric
func (m *Temporal) GetError() error {
	if m == nil {
		return errs.Wrap(cvsserr.ErrNoTemporalMetrics)
	}
	if err := m.Base.GetError(); err != nil {
		return errs.Wrap(err)
	}
	if m.IsEmpty() {
		return nil
	}
	switch true {
	case !m.E.IsValid(), !m.RL.IsValid(), !m.RC.IsValid():
		return errs.Wrap(cvsserr.ErrNoTemporalMetrics)
	default:
		return nil
	}
}

// IsEmpty returns true if all elements of Temporal Metrics are empty.
func (m *Temporal) IsEmpty() bool {
	return !m.names[metricE] && !m.names[metricRL] && !m.names[metricRC]
}

// Encode returns CVSSv2 vector string
func (m *Temporal) Encode() (string, error) {
	if m == nil {
		return "", errs.Wrap(cvsserr.ErrNoBaseMetrics)
	}
	r := &strings.Builder{}
	r.WriteString(m.Base.String()) //Vector of Base metrics
	if m.names[metricE] {
		r.WriteString(fmt.Sprintf("/%s:%v", metricE, m.E)) // Exploitability
	}
	if m.names[metricRL] {
		r.WriteString(fmt.Sprintf("/%s:%v", metricRL, m.RL)) // Remediation Level
	}
	if m.names[metricRC] {
		r.WriteString(fmt.Sprintf("/%s:%v", metricRC, m.RC)) // Report Conf
	}
	return r.String(), m.GetError()
}

// String is stringer method.
func (m *Temporal) String() string {
	s, _ := m.Encode()
	return s
}

// Score returns score of Temporal metrics
func (m *Temporal) Score() float64 {
	if err := m.GetError(); err != nil {
		return 0
	}
	bs := m.Base.Score()
	if m.IsEmpty() {
		return bs
	}
	return m.score(bs)
}

func (m *Temporal) score(baseScore float64) float64 {
	return roundTo1Decimal(baseScore * m.E.Value() * m.RL.Value() * m.RC.Value())
}

// GetSeverity returns severity by score of Base metrics
func (m *Temporal) Severity() Severity {
	return severity(m.Score())
}

// BaseMetrics returns Base metrics in Temporal metrics instance
func (m *Temporal) BaseMetrics() *Base {
	if m == nil {
		return nil
	}
	return m.Base
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
