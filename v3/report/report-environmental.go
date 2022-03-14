package report

import (
	"io"
	"strconv"

	"github.com/goark/errs"
	"github.com/goark/go-cvss/cvsserr"
	"github.com/goark/go-cvss/v3/metric"
	"github.com/goark/go-cvss/v3/report/names"
)

//CVSSReport is dataset for CVSS report
type EnvironmentalReport struct {
	*TemporalReport                                       //Report of Temporal metrics
	Vector                                         string //CVSS vector string
	EnvironmentalMetrics, EnvironmentalMetricValue string //titles
	CRName, CRValue                                string //Confidentiality Requirement
	IRName, IRValue                                string //Integrity Requirement
	ARName, ARValue                                string //Integrity Requirement
	MAVName, MAVValue                              string //Modified Attack Vector
	MACName, MACValue                              string //Modified Attack Complexity
	MPRName, MPRValue                              string //Modified Privileges Required
	MUIName, MUIValue                              string //Modified User Interaction
	MSName, MSValue                                string //Modified Scope
	MCName, MCValue                                string //Modified Confidentiality Impact
	MIName, MIValue                                string //Modified Integrity Impact
	MAName, MAValue                                string //Modified Availability Impact
	EnvironmentalScore                             string //Environmental Score
	SeverityName, SeverityValue                    string //Severity
}

//NewEnvironmental function reterns new CVSSReport instance
func NewEnvironmental(environmental *metric.Environmental, os ...ReportOptionsFunc) *EnvironmentalReport {
	opts := newOptions(os...)
	vec, _ := environmental.Encode()
	return &EnvironmentalReport{
		TemporalReport:           NewTemporal(environmental.TemporalMetrics(), os...),
		Vector:                   vec,
		EnvironmentalMetrics:     names.EnvironmentalMetrics(opts.lang),
		EnvironmentalMetricValue: names.EnvironmentalMetricsValueOf(opts.lang),
		CRName:                   names.ConfidentialityRequirement(opts.lang),
		CRValue:                  names.CRValueOf(environmental.CR, opts.lang),
		IRName:                   names.IntegrityRequirement(opts.lang),
		IRValue:                  names.IRValueOf(environmental.IR, opts.lang),
		ARName:                   names.AvailabilityRequirement(opts.lang),
		ARValue:                  names.ARValueOf(environmental.AR, opts.lang),
		MAVName:                  names.ModifiedAttackVector(opts.lang),
		MAVValue:                 names.MAVValueOf(environmental.MAV, opts.lang),
		MACName:                  names.ModifiedAttackComplexity(opts.lang),
		MACValue:                 names.MACValueOf(environmental.MAC, opts.lang),
		MPRName:                  names.ModifiedPrivilegesRequired(opts.lang),
		MPRValue:                 names.MPRValueOf(environmental.MPR, opts.lang),
		MUIName:                  names.ModifiedUserInteraction(opts.lang),
		MUIValue:                 names.MUIValueOf(environmental.MUI, opts.lang),
		MSName:                   names.ModifiedScope(opts.lang),
		MSValue:                  names.MSValueOf(environmental.MS, opts.lang),
		MCName:                   names.ModifiedConfidentialityImpact(opts.lang),
		MCValue:                  names.MCValueOf(environmental.MC, opts.lang),
		MIName:                   names.ModifiedIntegrityImpact(opts.lang),
		MIValue:                  names.MIValueOf(environmental.MI, opts.lang),
		MAName:                   names.ModifiedAvailabilityImpact(opts.lang),
		MAValue:                  names.MAValueOf(environmental.MA, opts.lang),
		EnvironmentalScore:       strconv.FormatFloat(environmental.Score(), 'f', -1, 64),
		SeverityName:             names.Severity(opts.lang),
		SeverityValue:            names.SeverityValueOf(environmental.Severity(), opts.lang),
	}
}

//ExportWithTemplate returns string of CVSS report
func (rep *EnvironmentalReport) ExportWith(r io.Reader) (io.Reader, error) {
	str, err := getTempleteString(r)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return rep.ExportWithString(str)
}

//ExportWithTemplate returns string of CVSS report
func (rep *EnvironmentalReport) ExportWithString(str string) (io.Reader, error) {
	if rep == nil {
		return nil, errs.Wrap(cvsserr.ErrNullPointer)
	}
	return executeTemplate(rep, str)
}

/* Copyright 2022 Spiegel
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
