package report

import (
	"bytes"
	"io"
	"strconv"
	"strings"
	"text/template"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/go-cvss/v3/metric"
	"github.com/spiegel-im-spiegel/go-cvss/v3/report/names"
	"golang.org/x/text/language"
)

const tempCsv = `{{ .BaseMetrics }},{{ .BaseMetricValue }}
CVSS Version,{{ .Version }}
{{ .AVName }},{{ .AVValue }}
{{ .ACName }},{{ .ACValue }}
{{ .PRName }},{{ .PRValue }}
{{ .UIName }},{{ .UIValue }}
{{ .SName }},{{ .SValue }}
{{ .CName }},{{ .CValue }}
{{ .IName }},{{ .IValue }}
{{ .AName }},{{ .AValue }}
Base Score,{{ .BaseScore }}
{{ .SeverityName }},{{ .SeverityValue }}
`

//CVSSReport is dataset for CVSS report
type CVSSReport struct {
	Version                      string //CVSS version
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
func NewBase(base *metric.Base, lang language.Tag) *CVSSReport {
	return &CVSSReport{
		Version:         base.Ver.String(),
		BaseMetrics:     names.BaseMetrics(lang),
		BaseMetricValue: names.BaseMetricsValueOf(lang),
		AVName:          names.AttackVector(lang),
		AVValue:         names.AVValueOf(base.AV, lang),
		ACName:          names.AttackComplexity(lang),
		ACValue:         names.ACValueOf(base.AC, lang),
		PRName:          names.PrivilegesRequired(lang),
		PRValue:         names.PRValueOf(base.PR, lang),
		UIName:          names.UserInteraction(lang),
		UIValue:         names.UIValueOf(base.UI, lang),
		SName:           names.Scope(lang),
		SValue:          names.SValueOf(base.S, lang),
		CName:           names.ConfidentialityImpact(lang),
		CValue:          names.CValueOf(base.C, lang),
		IName:           names.IntegrityImpact(lang),
		IValue:          names.IValueOf(base.I, lang),
		AName:           names.AvailabilityImpact(lang),
		AValue:          names.AValueOf(base.A, lang),
		BaseScore:       strconv.FormatFloat(base.Score(), 'f', -1, 64),
		SeverityName:    names.Severity(lang),
		SeverityValue:   names.SeverityValueOf(base.Severity(), lang),
	}
}

//ExportWithTemplate returns string of CVSS report
func (rep *CVSSReport) ExportWithTemplate(r io.Reader) (io.Reader, error) {
	buf := &bytes.Buffer{}
	if t, err := template.New("Repost").Parse(getTemplate(r)); err != nil {
		return buf, errs.Wrap(err)
	} else if err = t.Execute(buf, rep); err != nil {
		return nil, errs.Wrap(err)
	}
	return buf, nil
}

func getTemplate(r io.Reader) string {
	if r != nil {
		tmpdata := &strings.Builder{}
		if _, err := io.Copy(tmpdata, r); err != nil {
			return ""
		}
		return tmpdata.String()
	}
	return tempCsv
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
