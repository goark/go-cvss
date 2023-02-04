package metric

import (
	"fmt"
	"math"
	"strings"

	"github.com/goark/errs"
	"github.com/goark/go-cvss/cvsserr"
)

const (
	metricCDP = "CDP"
	metricTD  = "TD"
	metricCR  = "CR"
	metricIR  = "IR"
	metricAR  = "AR"
)

// Environmental is Environmental Metrics for CVSSv2
type Environmental struct {
	*Temporal
	CDP   CollateralDamagePotential
	TD    TargetDistribution
	CR    ConfidentialityRequirement
	IR    IntegrityRequirement
	AR    AvailabilityRequirement
	names map[string]bool
}

// NewBase returns Environmental Metrics instance
func NewEnvironmental() *Environmental {
	return &Environmental{
		Temporal: NewTemporal(),
		CDP:      CollateralDamagePotentialInvalid,
		TD:       TargetDistributionInvalid,
		CR:       ConfidentialityRequirementInvalid,
		IR:       IntegrityRequirementInvalid,
		AR:       AvailabilityRequirementInvalid,
		names:    map[string]bool{},
	}
}

// Decode returns Metrics instance by CVSSv2 vector
func (m *Environmental) Decode(vector string) (*Environmental, error) {
	if m == nil {
		m = NewEnvironmental()
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

func (m *Environmental) decodeOne(str string) error {
	if err := m.Temporal.decodeOne(str); err != nil {
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
	case metricCDP: // CollateralDamagePotential
		m.CDP = GetCollateralDamagePotential(elm[1])
		if m.CDP == CollateralDamagePotentialInvalid {
			return errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", str))
		}
	case metricTD: // TargetDistribution
		m.TD = GetTargetDistribution(elm[1])
		if m.TD == TargetDistributionInvalid {
			return errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", str))
		}
	case metricCR: // ConfidentialityRequirement
		m.CR = GetConfidentialityRequirement(elm[1])
		if m.CR == ConfidentialityRequirementInvalid {
			return errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", str))
		}
	case metricIR: // IntegrityRequirement
		m.IR = GetIntegrityRequirement(elm[1])
		if m.IR == IntegrityRequirementInvalid {
			return errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", str))
		}
	case metricAR: // AvailabilityRequirement
		m.AR = GetAvailabilityRequirement(elm[1])
		if m.AR == AvailabilityRequirementInvalid {
			return errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", str))
		}
	default:
		return errs.Wrap(cvsserr.ErrNotSupportMetric, errs.WithContext("vector", str))
	}
	m.names[name] = true
	return nil
}

// GetError returns error instance if undefined metric
func (m *Environmental) GetError() error {
	if m == nil {
		return errs.Wrap(cvsserr.ErrNoEnvironmentalMetrics)
	}
	if err := m.Temporal.GetError(); err != nil {
		return errs.Wrap(err)
	}
	if m.IsEmpty() {
		return nil
	}
	switch true {
	case !m.CDP.IsValid(), !m.TD.IsValid(), !m.CR.IsValid(), !m.IR.IsValid(), !m.AR.IsValid():
		return errs.Wrap(cvsserr.ErrNoEnvironmentalMetrics)
	default:
		return nil
	}
}

// IsEmpty returns true if all elements of Temporal Metrics are empty.
func (m *Environmental) IsEmpty() bool {
	return !m.names[metricCDP] && !m.names[metricTD] && !m.names[metricCR] && !m.names[metricIR] && !m.names[metricAR]
}

// Encode returns CVSSv2 vector string
func (m *Environmental) Encode() (string, error) {
	if m == nil {
		return "", errs.Wrap(cvsserr.ErrNoBaseMetrics)
	}
	r := &strings.Builder{}
	r.WriteString(m.Temporal.String()) //Vector of Temporal metrics
	if m.names[metricCDP] {
		r.WriteString(fmt.Sprintf("/%s:%v", metricCDP, m.CDP)) // Collateral Damage Potential
	}
	if m.names[metricTD] {
		r.WriteString(fmt.Sprintf("/%s:%v", metricTD, m.TD)) // Target Distribution
	}
	if m.names[metricCR] {
		r.WriteString(fmt.Sprintf("/%s:%v", metricCR, m.CR)) // Confidentiality Requirement
	}
	if m.names[metricIR] {
		r.WriteString(fmt.Sprintf("/%s:%v", metricIR, m.IR)) // Integrity Requirement
	}
	if m.names[metricAR] {
		r.WriteString(fmt.Sprintf("/%s:%v", metricAR, m.AR)) // Availability Requirement
	}
	return r.String(), m.GetError()
}

// String is stringer method.
func (m *Environmental) String() string {
	s, _ := m.Encode()
	return s
}

// Score returns score of Environmental metrics
func (m *Environmental) Score() float64 {
	if err := m.GetError(); err != nil {
		return 0
	}
	var baseScore float64
	if m.IsEmpty() {
		baseScore = m.Base.Score()
	} else {
		adjustedImpact := math.Min(10.0, roundTo4Decimal(10.41*(1-(1-m.C.Value()*m.CR.Value())*(1-m.I.Value()*m.IR.Value())*(1-m.A.Value()*m.AR.Value()))))
		baseScore = m.Base.score(adjustedImpact)
	}
	var adjustedTemporal float64
	if m.Temporal.IsEmpty() {
		adjustedTemporal = baseScore
	} else {
		adjustedTemporal = m.Temporal.score(baseScore)
	}
	if m.IsEmpty() {
		return adjustedTemporal
	}
	return roundTo1Decimal(adjustedTemporal + (10-adjustedTemporal)*m.CDP.Value()*m.TD.Value())
}

// Severity returns severity by score of Environmental metrics
func (m *Environmental) Severity() Severity {
	return severity(m.Score())
}

// BaseMetrics returns Base metrics in Environmental metrics instance
func (m *Environmental) BaseMetrics() *Base {
	if m == nil {
		return nil
	}
	return m.Base
}

// TemporalMetrics returns Temporal metrics in Environmental metrics instance
func (m *Environmental) TemporalMetrics() *Temporal {
	if m == nil {
		return nil
	}
	return m.Temporal
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
