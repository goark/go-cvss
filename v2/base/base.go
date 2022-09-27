package base

import (
	"fmt"
	"math"
	"strings"

	"github.com/goark/errs"
	"github.com/goark/go-cvss/cvsserr"
)

// Metrics is Base Metrics for CVSSv2
type Metrics struct {
	AV AccessVector
	AC AccessComplexity
	Au Authentication
	C  ConfidentialityImpact
	I  IntegrityImpact
	A  AvailabilityImpact
	E  Exploitability
	RL RemediationLevel
	RC ReportConfidence
}

// NewMetrics returns Metrics instance
func NewMetrics() *Metrics {
	return &Metrics{
		AV: AccessVectorUnknown,
		AC: AccessComplexityUnknown,
		Au: AuthenticationUnknown,
		C:  ConfidentialityImpactUnknown,
		I:  IntegrityImpactUnknown,
		A:  AvailabilityImpactUnknown,
		E:  ExploitabilityNotDefined,
		RL: RemediationLevelNotDefined,
		RC: ReportConfidenceNotDefined,
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
		if len(metric) != 2 {
			return nil, errs.Wrap(cvsserr.ErrInvalidVector, errs.WithContext("vector", vector))
		}
		switch strings.ToUpper(metric[0]) {
		case "AV": // Access Vector
			metrics.AV = GetAccessVector(metric[1])
		case "AC": // Access Complexity
			metrics.AC = GetAccessComplexity(metric[1])
		case "AU": // Authentication
			metrics.Au = GetAuthentication(metric[1])
		case "C": // Confidentiality Impact
			metrics.C = GetConfidentialityImpact(metric[1])
		case "I": // Integrity Impact
			metrics.I = GetIntegrityImpact(metric[1])
		case "A": // Availability Impact
			metrics.A = GetAvailabilityImpact(metric[1])
		case "E": // Exploitability
			metrics.E = GetExploitability(metric[1])
		case "RL": // RemediationLevel
			metrics.RL = GetRemediationLevel(metric[1])
		case "RC": // RemediationLevel
			metrics.RC = GetReportConfidence(metric[1])
		default:
			return nil, errs.Wrap(cvsserr.ErrInvalidVector, errs.WithContext("vector", value))
		}
	}
	return metrics, metrics.GetError()
}

// Encode returns CVSSv3 vector string
func (m *Metrics) Encode() (string, error) {
	if err := m.GetError(); err != nil {
		return "", err
	}
	r := &strings.Builder{}
	r.WriteString(fmt.Sprintf("AV:%v", m.AV))  // Access Vector
	r.WriteString(fmt.Sprintf("/AC:%v", m.AC)) // Access Complexity
	r.WriteString(fmt.Sprintf("/Au:%v", m.Au)) // Authentication
	r.WriteString(fmt.Sprintf("/C:%v", m.C))   // Confidentiality Impact
	r.WriteString(fmt.Sprintf("/I:%v", m.I))   // Integrity Impact
	r.WriteString(fmt.Sprintf("/A:%v", m.A))   // Availability Impact

	if m.E.IsDefined() {
		r.WriteString(fmt.Sprintf("/E:%v", m.E)) // Exploitability
	}

	if m.RL.IsDefined() {
		r.WriteString(fmt.Sprintf("/RL:%v", m.RL)) // Remediation Level
	}

	if m.RC.IsDefined() {
		r.WriteString(fmt.Sprintf("/RC:%v", m.RC)) // Report Confidence
	}

	return r.String(), nil
}

// GetError returns error instance if undefined metric
func (m *Metrics) GetError() error {
	if m == nil {
		return errs.Wrap(cvsserr.ErrUndefinedMetric)
	}
	switch true {
	case !m.AV.IsDefined(), !m.AC.IsDefined(), !m.Au.IsDefined(), !m.C.IsDefined(), !m.I.IsDefined(), !m.A.IsDefined():
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

func (m *Metrics) TemporalScore() float64 {
	return math.Round(m.Score()*m.E.Value()*m.RL.Value()*m.RC.Value()*10) / 10
}

/* Copyright 2022 luxifer */
