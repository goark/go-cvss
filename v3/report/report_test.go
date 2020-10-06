package report

import (
	"io"
	"strings"
	"testing"

	"github.com/spiegel-im-spiegel/go-cvss/v3/metric"
	"golang.org/x/text/language"
)

const (
	tstMd = `- CVSS Version {{ .Version }}
- {{ .SeverityName }}: {{ .SeverityValue }} ({{ .BaseScore }})

| {{ .BaseMetrics }} | {{ .BaseMetricValue }} |
|--------|-------|
| {{ .AVName }} | {{ .AVValue }} |
| {{ .ACName }} | {{ .ACValue }} |
| {{ .PRName }} | {{ .PRValue }} |
| {{ .UIName }} | {{ .UIValue }} |
| {{ .SName }} | {{ .SValue }} |
| {{ .CName }} | {{ .CValue }} |
| {{ .IName }} | {{ .IValue }} |
| {{ .AName }} | {{ .AValue }} |
`
	tstResCsv = `Base Metrics,Metric Value
CVSS Version,3.0
Attack Vector,Network
Attack Complexity,Low
Privileges Required,None
User Interaction,None
Scope,Unchanged
Confidentiality Impact,High
Integrity Impact,High
Availability Impact,High
Base Score,9.8
Severity,Critical
`
	tstResMd = `- CVSS Version 3.0
- Severity: Critical (9.8)

| Base Metrics | Metric Value |
|--------|-------|
| Attack Vector | Network |
| Attack Complexity | Low |
| Privileges Required | None |
| User Interaction | None |
| Scope | Unchanged |
| Confidentiality Impact | High |
| Integrity Impact | High |
| Availability Impact | High |
`
)

func TestReport(t *testing.T) {
	testCases := []struct {
		vector  string
		tmpdata string
		lang    language.Tag
		rep     string
	}{
		{vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", tmpdata: "", lang: language.English, rep: tstResCsv},
		{vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", tmpdata: tstMd, lang: language.English, rep: tstResMd},
	}

	for _, tc := range testCases {
		m, err := metric.NewBase().Decode(tc.vector)
		if err != nil {
			t.Errorf("Metrics.Decode(%v) = \"%v\", want nil.", tc.vector, err)
		}
		var tr io.Reader
		if len(tc.tmpdata) > 0 {
			tr = strings.NewReader(tc.tmpdata)
		}
		bldr := &strings.Builder{}
		r, err := NewBase(m, tc.lang).ExportWithTemplate(tr)
		if err != nil {
			t.Errorf("Metrics.Report(%v) = \"%v\", want nil.", tc.lang, err)
		}
		if _, err := io.Copy(bldr, r); err != nil {
			t.Errorf("Metrics.Report(nil, %v) = \"%v\", want nil.", tc.lang, err)
		}
		rep := bldr.String()
		if rep != tc.rep {
			t.Errorf("Metrics.Report(nil, %v) = \"%v\", want \"%v\".", tc.lang, rep, tc.rep)
		}

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
