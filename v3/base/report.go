package base

import (
	"bytes"
	"io"
	"strings"
	"text/template"

	"golang.org/x/text/language"
)

const tempCsv = `{{ .BaseMetrics }},{{ .MetricValue }}
{{ .AVName }},{{ .AVValue }}
{{ .ACName }},{{ .ACValue }}
{{ .PRName }},{{ .PRValue }}
{{ .UIName }},{{ .UIValue }}
{{ .SName }},{{ .SValue }}
{{ .CName }},{{ .CValue }}
{{ .IName }},{{ .IValue }}
{{ .AName }},{{ .AValue }}
`

//CVSSReport is dataset for CVSS report
type CVSSReport struct {
	BaseMetrics, MetricValue string //titles
	AVName, AVValue          string //AttackVector
	ACName, ACValue          string //AttackComplexity
	PRName, PRValue          string //PrivilegesRequired
	UIName, UIValue          string //UserInteraction
	SName, SValue            string //Scope
	CName, CValue            string //ConfidentialityImpact
	IName, IValue            string //IntegrityImpact
	AName, AValue            string //AvailabilityImpact
}

//Report returns string of CVSS report
func (m *Metrics) Report(r io.Reader, lang language.Tag) (io.Reader, error) {
	buf := &bytes.Buffer{}
	if t, err := template.New("Repost").Parse(getTemplate(r)); err != nil {
		return buf, err
	} else if err = t.Execute(buf, m.getReport(lang)); err != nil {
		return nil, err
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

func (m *Metrics) getReport(lang language.Tag) *CVSSReport {
	return &CVSSReport{
		BaseMetrics: m.Title(lang),
		MetricValue: m.NameOfvalue(lang),
		AVName:      m.AV.Title(lang),
		AVValue:     m.AV.NameOfValue(lang),
		ACName:      m.AC.Title(lang),
		ACValue:     m.AC.NameOfValue(lang),
		PRName:      m.PR.Title(lang),
		PRValue:     m.PR.NameOfValue(lang),
		UIName:      m.UI.Title(lang),
		UIValue:     m.UI.NameOfValue(lang),
		SName:       m.S.Title(lang),
		SValue:      m.S.NameOfValue(lang),
		CName:       m.C.Title(lang),
		CValue:      m.C.NameOfValue(lang),
		IName:       m.I.Title(lang),
		IValue:      m.I.NameOfValue(lang),
		AName:       m.A.Title(lang),
		AValue:      m.A.NameOfValue(lang),
	}
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
