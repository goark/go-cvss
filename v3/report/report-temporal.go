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
type TemporalReport struct {
	*BaseReport                                 //Report of Base metrics
	Vector                               string //CVSS vector string
	TemporalMetrics, TemporalMetricValue string //titles
	EName, EValue                        string //Exploitability
	RLName, RLValue                      string //RemediationLevel
	RCName, RCValue                      string //ReportConfidence
	TemporalScore                        string //Temporal Score
	SeverityName, SeverityValue          string //Severity
}

//NewtBase function reterns new CVSSReport instance
func NewTemporal(temporal *metric.Temporal, os ...ReportOptionsFunc) *TemporalReport {
	opts := newOptions(os...)
	vec, _ := temporal.Encode()
	return &TemporalReport{
		BaseReport:          NewBase(temporal.BaseMetrics(), os...),
		Vector:              vec,
		TemporalMetrics:     names.TemporalMetrics(opts.lang),
		TemporalMetricValue: names.TemporalMetricsValueOf(opts.lang),
		EName:               names.Exploitability(opts.lang),
		EValue:              names.EValueOf(temporal.E, opts.lang),
		RLName:              names.RemediationLevel(opts.lang),
		RLValue:             names.RLValueOf(temporal.RL, opts.lang),
		RCName:              names.ReportConfidence(opts.lang),
		RCValue:             names.RCValueOf(temporal.RC, opts.lang),
		TemporalScore:       strconv.FormatFloat(temporal.Score(), 'f', -1, 64),
		SeverityName:        names.Severity(opts.lang),
		SeverityValue:       names.SeverityValueOf(temporal.Severity(), opts.lang),
	}
}

//ExportWithTemplate returns string of CVSS report
func (rep *TemporalReport) ExportWith(r io.Reader) (io.Reader, error) {
	str, err := getTempleteString(r)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return rep.ExportWithString(str)
}

//ExportWithTemplate returns string of CVSS report
func (rep *TemporalReport) ExportWithString(str string) (io.Reader, error) {
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
