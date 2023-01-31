package base

import (
	"fmt"
	"math"
	"strings"

	"github.com/goark/errs"
	"github.com/goark/go-cvss/cvsserr"
)

const (
	metricAV  = "AV"
	metricAC  = "AC"
	metricAu  = "Au"
	metricC   = "C"
	metricI   = "I"
	metricA   = "A"
	metricE   = "E"
	metricRL  = "RL"
	metricRC  = "RC"
	metricCDP = "CDP"
	metricTD  = "TD"
	metricCR  = "CR"
	metricIR  = "IR"
	metricAR  = "AR"
)

// Metrics is Base Metrics for CVSSv2
type Metrics struct {
	AV    AccessVector
	AC    AccessComplexity
	Au    Authentication
	C     ConfidentialityImpact
	I     IntegrityImpact
	A     AvailabilityImpact
	E     Exploitability
	RL    RemediationLevel
	RC    ReportConfidence
	CDP   CollateralDamagePotential
	TD    TargetDistribution
	CR    ConfidentialityRequirement
	IR    IntegrityRequirement
	AR    AvailabilityRequirement
	names map[string]bool
}

// NewMetrics returns Metrics instance
func NewMetrics() *Metrics {
	return &Metrics{
		AV:    AccessVectorUnknown,
		AC:    AccessComplexityUnknown,
		Au:    AuthenticationUnknown,
		C:     ConfidentialityImpactUnknown,
		I:     IntegrityImpactUnknown,
		A:     AvailabilityImpactUnknown,
		E:     ExploitabilityNotDefined,
		RL:    RemediationLevelNotDefined,
		RC:    ReportConfidenceNotDefined,
		CDP:   CollateralDamagePotentialNotDefined,
		TD:    TargetDistributionNotDefined,
		CR:    ConfidentialityRequirementNotDefined,
		IR:    IntegrityRequirementNotDefined,
		AR:    AvailabilityRequirementNotDefined,
		names: map[string]bool{},
	}
}

// Decode returns Metrics instance by CVSSv2 vector
func Decode(vector string) (*Metrics, error) {
	values := strings.Split(vector, "/")
	if len(values) < 6 {
		return nil, errs.Wrap(cvsserr.ErrInvalidVector, errs.WithContext("vector", vector))
	}
	// metrics
	metrics := NewMetrics()
	for _, value := range values {
		metric := strings.Split(value, ":")
		if len(metric) != 2 || len(metric[0]) == 0 || len(metric[1]) == 0 {
			return nil, errs.Wrap(cvsserr.ErrInvalidVector, errs.WithContext("vector", vector))
		}
		name := metric[0]
		if metrics.names[name] {
			return nil, errs.Wrap(cvsserr.ErrSameMetric, errs.WithContext("metric", metric))
		}
		switch name {
		case metricAV: // Access Vector
			metrics.AV = GetAccessVector(metric[1])
			if metrics.AV == AccessVectorUnknown {
				return nil, errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", metric))
			}
		case metricAC: // Access Complexity
			metrics.AC = GetAccessComplexity(metric[1])
			if metrics.AC == AccessComplexityUnknown {
				return nil, errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", metric))
			}
		case metricAu: // Authentication
			metrics.Au = GetAuthentication(metric[1])
			if metrics.Au == AuthenticationUnknown {
				return nil, errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", metric))
			}
		case metricC: // Confidentiality Impact
			metrics.C = GetConfidentialityImpact(metric[1])
			if metrics.C == ConfidentialityImpactUnknown {
				return nil, errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", metric))
			}
		case metricI: // Integrity Impact
			metrics.I = GetIntegrityImpact(metric[1])
			if metrics.I == IntegrityImpactUnknown {
				return nil, errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", metric))
			}
		case metricA: // Availability Impact
			metrics.A = GetAvailabilityImpact(metric[1])
			if metrics.A == AvailabilityImpactUnknown {
				return nil, errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", metric))
			}
		case metricE: // Exploitability
			metrics.E = GetExploitability(metric[1])
			if metrics.E == ExploitabilityInvalid {
				return nil, errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", metric))
			}
		case metricRL: // RemediationLevel
			metrics.RL = GetRemediationLevel(metric[1])
			if metrics.RL == RemediationLevelInvalid {
				return nil, errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", metric))
			}
		case metricRC: // RemediationLevel
			metrics.RC = GetReportConfidence(metric[1])
			if metrics.RC == ReportConfidenceInvalid {
				return nil, errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", metric))
			}
		case metricCDP: // CollateralDamagePotential
			metrics.CDP = GetCollateralDamagePotential(metric[1])
			if metrics.CDP == CollateralDamagePotentialInvalid {
				return nil, errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", metric))
			}
		case metricTD: // TargetDistribution
			metrics.TD = GetTargetDistribution(metric[1])
			if metrics.TD == TargetDistributionInvalid {
				return nil, errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", metric))
			}
		case metricCR: // ConfidentialityRequirement
			metrics.CR = GetConfidentialityRequirement(metric[1])
			if metrics.CR == ConfidentialityRequirementInvalid {
				return nil, errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", metric))
			}
		case metricIR: // IntegrityRequirement
			metrics.IR = GetIntegrityRequirement(metric[1])
			if metrics.IR == IntegrityRequirementInvalid {
				return nil, errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", metric))
			}
		case metricAR: // AvailabilityRequirement
			metrics.AR = GetAvailabilityRequirement(metric[1])
			if metrics.AR == AvailabilityRequirementInvalid {
				return nil, errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", metric))
			}
		default:
			return nil, errs.Wrap(cvsserr.ErrNotSupportMetric, errs.WithContext("vector", value))
		}
		metrics.names[name] = true
	}
	return metrics, metrics.GetError()
}

// Encode returns CVSSv3 vector string
func (m *Metrics) Encode() (string, error) {
	if err := m.GetError(); err != nil {
		return "", err
	}
	r := &strings.Builder{}

	// Base metrics
	r.WriteString(fmt.Sprintf("%s:%v", metricAV, m.AV))  // Access Vector
	r.WriteString(fmt.Sprintf("/%s:%v", metricAC, m.AC)) // Access Complexity
	r.WriteString(fmt.Sprintf("/%s:%v", metricAu, m.Au)) // Authentication
	r.WriteString(fmt.Sprintf("/%s:%v", metricC, m.C))   // Confidentiality Impact
	r.WriteString(fmt.Sprintf("/%s:%v", metricI, m.I))   // Integrity Impact
	r.WriteString(fmt.Sprintf("/%s:%v", metricA, m.A))   // Availability Impact

	// Temporal metrics
	if m.names[metricE] || m.names[metricRL] || m.names[metricRC] {
		r.WriteString(fmt.Sprintf("/%s:%v", metricE, m.E))   // Exploitability
		r.WriteString(fmt.Sprintf("/%s:%v", metricRL, m.RL)) // Remediation Level
		r.WriteString(fmt.Sprintf("/%s:%v", metricRC, m.RC)) // Report Confidence
	}

	// Environmental metrics
	if m.names[metricCDP] || m.names[metricTD] || m.names[metricCR] || m.names[metricIR] || m.names[metricAR] {
		r.WriteString(fmt.Sprintf("/%s:%v", metricCDP, m.CDP)) // Collateral Damage Potential
		r.WriteString(fmt.Sprintf("/%s:%v", metricTD, m.TD))   // Target Distribution
		r.WriteString(fmt.Sprintf("/%s:%v", metricCR, m.CR))   // Confidentiality Requirement
		r.WriteString(fmt.Sprintf("/%s:%v", metricIR, m.IR))   // Integrity Requirement
		r.WriteString(fmt.Sprintf("/%s:%v", metricAR, m.AR))   // Availability Requirement
	}

	return r.String(), nil
}

// String is stringer method.
func (m *Metrics) String() string {
	s, _ := m.Encode()
	return s
}

// GetError returns error instance if undefined metric
func (m *Metrics) GetError() error {
	if m == nil {
		return errs.Wrap(cvsserr.ErrUndefinedMetric)
	}
	switch true {
	case !m.AV.IsDefined(), !m.AC.IsDefined(), !m.Au.IsDefined(), !m.C.IsDefined(), !m.I.IsDefined(), !m.A.IsDefined(),
		!m.E.IsValid(), !m.RL.IsValid(), !m.RC.IsValid(),
		!m.CDP.IsValid(), !m.TD.IsValid(), !m.CR.IsValid(), !m.IR.IsValid(), !m.AR.IsValid():
		return errs.Wrap(cvsserr.ErrUndefinedMetric)
	default:
		return nil
	}
}

// Score returns score of Base metrics
func (m *Metrics) Score() float64 {
	if err := m.GetError(); err != nil {
		return 0
	}
	impact := 10.41 * (1 - (1-m.C.Value())*(1-m.I.Value())*(1-m.A.Value()))
	return m.baseScore(impact)
}

func (m *Metrics) baseScore(impact float64) float64 {
	if err := m.GetError(); err != nil {
		return 0
	}
	exploitability := 20 * m.AV.Value() * m.AC.Value() * m.Au.Value()
	fimpact := 1.176
	if impact == 0 {
		fimpact = 0
	}
	return math.Round(((0.6*impact)+(0.4*exploitability)-1.5)*fimpact*10) / 10
}

// GetSeverity returns severity by score of Base metrics
func (m *Metrics) GetSeverity() Severity {
	score := m.Score()
	switch true {
	case score >= 0 && score < 4.0:
		return SeverityLow
	case score >= 4.0 && score < 7.0:
		return SeverityMedium
	case score >= 7.0:
		return SeverityHigh
	default:
		return SeverityUnknown
	}
}

// TemporalScore returns score of Temporal metrics
func (m *Metrics) TemporalScore() float64 {
	return m.temporalScore(m.Score())
}

func (m *Metrics) temporalScore(baseScore float64) float64 {
	return math.Round(baseScore*m.E.Value()*m.RL.Value()*m.RC.Value()*10) / 10
}

// EnvironmentalScore returns score of Environmental metrics
func (m *Metrics) EnvironmentalScore() float64 {
	adjustedImpact := math.Min(10.0, 10.41*(1-(1-m.C.Value()*m.CR.Value())*(1-m.I.Value()*m.IR.Value())*(1-m.A.Value()*m.AR.Value())))
	baseScore := m.baseScore(adjustedImpact)
	adjustedTemporal := m.temporalScore(baseScore)
	return math.Round((adjustedTemporal+(10-adjustedTemporal)*m.CDP.Value()*m.TD.Value())*10) / 10
}

/* Copyright 2022 luxifer */
/* Contributed by Spiegel, 2023 */
