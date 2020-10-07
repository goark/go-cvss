package report

import (
	"io"
	"strconv"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/go-cvss/cvsserr"
	"github.com/spiegel-im-spiegel/go-cvss/v3/metric"
	"github.com/spiegel-im-spiegel/go-cvss/v3/report/names"
)

//CVSSReport is dataset for CVSS report
type BaseReport struct {
	Version                      string //CVSS version
	Vector                       string //CVSS vector string
	BaseMetrics, BaseMetricValue string //titles
	AVName, AVValue              string //AttackVector
	ACName, ACValue              string //AttackComplexity
	PRName, PRValue              string //PrivilegesRequired
	UIName, UIValue              string //UserInteraction
	SName, SValue                string //Scope
	CName, CValue                string //ConfidentialityImpact
	IName, IValue                string //IntegrityImpact
	AName, AValue                string //AvailabilityImpact
	BaseScore                    string //Base Score
	SeverityName, SeverityValue  string //Severity
}

//NewtBase function reterns new CVSSReport instance
func NewBase(base *metric.Base, os ...ReportOptionsFunc) *BaseReport {
	opts := newOptions(os...)
	vec, _ := base.Encode()
	return &BaseReport{
		Version:         base.Ver.String(),
		Vector:          vec,
		BaseMetrics:     names.BaseMetrics(opts.lang),
		BaseMetricValue: names.BaseMetricsValueOf(opts.lang),
		AVName:          names.AttackVector(opts.lang),
		AVValue:         names.AVValueOf(base.AV, opts.lang),
		ACName:          names.AttackComplexity(opts.lang),
		ACValue:         names.ACValueOf(base.AC, opts.lang),
		PRName:          names.PrivilegesRequired(opts.lang),
		PRValue:         names.PRValueOf(base.PR, opts.lang),
		UIName:          names.UserInteraction(opts.lang),
		UIValue:         names.UIValueOf(base.UI, opts.lang),
		SName:           names.Scope(opts.lang),
		SValue:          names.SValueOf(base.S, opts.lang),
		CName:           names.ConfidentialityImpact(opts.lang),
		CValue:          names.CValueOf(base.C, opts.lang),
		IName:           names.IntegrityImpact(opts.lang),
		IValue:          names.IValueOf(base.I, opts.lang),
		AName:           names.AvailabilityImpact(opts.lang),
		AValue:          names.AValueOf(base.A, opts.lang),
		BaseScore:       strconv.FormatFloat(base.Score(), 'f', -1, 64),
		SeverityName:    names.Severity(opts.lang),
		SeverityValue:   names.SeverityValueOf(base.Severity(), opts.lang),
	}
}

//ExportWithTemplate returns string of CVSS report
func (rep *BaseReport) ExportWith(r io.Reader) (io.Reader, error) {
	str, err := getTempleteString(r)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return rep.ExportWithString(str)
}

//ExportWithTemplate returns string of CVSS report
func (rep *BaseReport) ExportWithString(str string) (io.Reader, error) {
	if rep == nil {
		return nil, errs.Wrap(cvsserr.ErrNullPointer)
	}
	return executeTemplate(rep, str)
}

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
