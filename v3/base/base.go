package base

import (
	"fmt"
	"math"
	"strings"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/go-cvss/cvsserr"
	"github.com/spiegel-im-spiegel/go-cvss/v3/version"
)

//Metrics is Base Metrics for CVSSv3
type Metrics struct {
	Ver version.Num
	AV  AttackVector
	AC  AttackComplexity
	PR  PrivilegesRequired
	UI  UserInteraction
	S   Scope
	C   ConfidentialityImpact
	I   IntegrityImpact
	A   AvailabilityImpact
	E   Exploitability
	RL  RemediationLevel
	RC  ReportConfidence
}

//NewMetrics returns Metrics instance
func NewMetrics() *Metrics {
	return &Metrics{
		Ver: version.Unknown,
		AV:  AttackVectorUnknown,
		AC:  AttackComplexityUnknown,
		PR:  PrivilegesRequiredUnknown,
		UI:  UserInteractionUnknown,
		S:   ScopeUnknown,
		C:   ConfidentialityImpactUnknown,
		I:   IntegrityImpactUnknown,
		A:   AvailabilityImpactUnknown,
		E:   ExploitabilityNotDefined,
		RL:  RemediationLevelNotDefined,
		RC:  ReportConfidenceNotDefined,
	}
}

//Decode returns Metrics instance by CVSSv3 vector
func Decode(vector string) (*Metrics, error) {
	values := strings.Split(vector, "/")
	if len(values) < 9 {
		return nil, errs.Wrap(cvsserr.ErrInvalidVector, errs.WithContext("vector", vector))
	}
	//CVSS version
	num, err := checkVersion(values[0])
	if err != nil {
		return nil, errs.Wrap(err, errs.WithContext("vector", vector))
	}
	if num == version.Unknown {
		return nil, errs.Wrap(cvsserr.ErrNotSupportVer, errs.WithContext("vector", vector))
	}
	//metrics
	metrics := NewMetrics()
	metrics.Ver = num
	for _, value := range values[1:] {
		metric := strings.Split(value, ":")
		if len(metric) != 2 {
			return nil, errs.Wrap(cvsserr.ErrInvalidVector, errs.WithContext("vector", vector))
		}
		switch strings.ToUpper(metric[0]) {
		case "AV": //Attack Vector
			metrics.AV = GetAttackVector(metric[1])
		case "AC": //Attack Complexity
			metrics.AC = GetAttackComplexity(metric[1])
		case "PR": //Privileges Required
			metrics.PR = GetPrivilegesRequired(metric[1])
		case "UI": //User Interaction
			metrics.UI = GetUserInteraction(metric[1])
		case "S": //Scope
			metrics.S = GetScope(metric[1])
		case "C": //Confidentiality Impact
			metrics.C = GetConfidentialityImpact(metric[1])
		case "I": //Integrity Impact
			metrics.I = GetIntegrityImpact(metric[1])
		case "A": //Availability Impact
			metrics.A = GetAvailabilityImpact(metric[1])
		case "E": //Exploitability
			metrics.E = GetExploitability(metric[1])
		case "RL": //RemediationLevel
			metrics.RL = GetRemediationLevel(metric[1])
		case "RC": //RemediationLevel
			metrics.RC = GetReportConfidence(metric[1])
		default:
			return nil, errs.Wrap(cvsserr.ErrInvalidVector, errs.WithContext("vector", value))
		}
	}
	return metrics, metrics.GetError()
}
func checkVersion(ver string) (version.Num, error) {
	v := strings.Split(ver, ":")
	if len(v) != 2 {
		return version.Unknown, errs.Wrap(cvsserr.ErrInvalidVector, errs.WithContext("vector", ver))
	}
	if strings.ToUpper(v[0]) != "CVSS" {
		return version.Unknown, errs.Wrap(cvsserr.ErrInvalidVector, errs.WithContext("vector", ver))
	}
	return version.Get(v[1]), nil
}

//Encode returns CVSSv3 vector string
func (m *Metrics) Encode() (string, error) {
	if err := m.GetError(); err != nil {
		return "", err
	}
	r := &strings.Builder{}
	r.WriteString("CVSS:" + m.Ver.String())    //CVSS Version
	r.WriteString(fmt.Sprintf("/AV:%v", m.AV)) //Attack Vector
	r.WriteString(fmt.Sprintf("/AC:%v", m.AC)) //Attack Complexity
	r.WriteString(fmt.Sprintf("/PR:%v", m.PR)) //Privileges Required
	r.WriteString(fmt.Sprintf("/UI:%v", m.UI)) //User Interaction
	r.WriteString(fmt.Sprintf("/S:%v", m.S))   //Scope
	r.WriteString(fmt.Sprintf("/C:%v", m.C))   //Confidentiality Impact
	r.WriteString(fmt.Sprintf("/I:%v", m.I))   //Integrity Impact
	r.WriteString(fmt.Sprintf("/A:%v", m.A))   //Availability Impact

	if m.E.IsDefined() {
		r.WriteString(fmt.Sprintf("/E:%v", m.E)) //Exploitability
	}

	if m.RL.IsDefined() {
		r.WriteString(fmt.Sprintf("/RL:%v", m.RL)) //Remediation Level
	}

	if m.RC.IsDefined() {
		r.WriteString(fmt.Sprintf("/RC:%v", m.RC)) //Report Confidence
	}

	return r.String(), nil
}

//GetError returns error instance if undefined metric
func (m *Metrics) GetError() error {
	if m == nil {
		return errs.Wrap(cvsserr.ErrUndefinedMetric)
	}
	switch true {
	case !m.AV.IsDefined(), !m.AC.IsDefined(), !m.PR.IsDefined(), !m.UI.IsDefined(), !m.S.IsDefined(), !m.C.IsDefined(), !m.I.IsDefined(), !m.A.IsDefined():
		return errs.Wrap(cvsserr.ErrUndefinedMetric)
	default:
		return nil
	}
}

//Score returns score of Base metrics
func (m *Metrics) Score() float64 {
	if err := m.GetError(); err != nil {
		return 0.0
	}

	impact := 1.0 - (1-m.C.Value())*(1-m.I.Value())*(1-m.A.Value())
	if m.S == ScopeUnchanged {
		impact *= 6.42
	} else {
		impact = 7.52*(impact-0.029) - 3.25*math.Pow(impact-0.02, 15.0)
	}
	ease := 8.22 * m.AV.Value() * m.AC.Value() * m.PR.Value(m.S) * m.UI.Value()

	var score float64
	if impact <= 0 {
		score = 0.0
	} else if m.S == ScopeUnchanged {
		score = roundUp(math.Min(impact+ease, 10))
	} else {
		score = roundUp(math.Min(1.08*(impact+ease), 10))
	}
	return score
}

//GetSeverity returns severity by score of Base metrics
func (m *Metrics) GetSeverity() Severity {
	score := m.Score()
	switch true {
	case score == 0:
		return SeverityNone
	case score > 0 && score < 4.0:
		return SeverityLow
	case score >= 4.0 && score < 7.0:
		return SeverityMedium
	case score >= 7.0 && score < 9.0:
		return SeverityHigh
	case score >= 9.0:
		return SeverityCritical
	default:
		return SeverityUnknown
	}
}

func (m *Metrics) TemporalScore() float64 {
	return roundUp(m.Score() * m.E.Value() * m.RL.Value() * m.RC.Value())
}

func roundUp(input float64) float64 {
	intInput := math.Round(input * 100000)

	if int(intInput)%10000 == 0 {
		return intInput / 100000
	}

	return (math.Floor(intInput/10000) + 1) / 10.0
}

/* Contributed by Florent Viel, 2020 */
/* Copyright 2018-2020 Spiegel
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
