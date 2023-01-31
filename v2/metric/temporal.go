package metric

import (
	"fmt"
	"math"
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
	return m, m.GetError()
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
		return errs.Wrap(cvsserr.ErrNoMetrics)
	}
	if err := m.Base.GetError(); err != nil {
		return errs.Wrap(err)
	}
	switch true {
	case !m.E.IsValid(), !m.RL.IsValid(), !m.RC.IsValid():
		return errs.Wrap(cvsserr.ErrNoMetrics)
	default:
		return nil
	}
}

// Encode returns CVSSv2 vector string
func (m *Temporal) Encode() (string, error) {
	if err := m.GetError(); err != nil {
		return "", err
	}
	bs, err := m.Base.Encode()
	if err != nil {
		return "", errs.Wrap(err)
	}
	r := &strings.Builder{}
	r.WriteString(bs) //Vector of Base metrics
	if m.names[metricE] || m.names[metricRL] || m.names[metricRC] {
		r.WriteString(fmt.Sprintf("/%s:%v", metricE, m.E))   // Exploitability
		r.WriteString(fmt.Sprintf("/%s:%v", metricRL, m.RL)) // Remediation Level
		r.WriteString(fmt.Sprintf("/%s:%v", metricRC, m.RC)) // Report Conf
	}
	return r.String(), nil
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
	return m.score(m.Base.Score())
}

func (m *Temporal) score(baseScore float64) float64 {
	return math.Round(baseScore*m.E.Value()*m.RL.Value()*m.RC.Value()*10) / 10
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
