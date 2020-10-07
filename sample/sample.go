package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spiegel-im-spiegel/go-cvss/v3/metric"
	"github.com/spiegel-im-spiegel/go-cvss/v3/report"
)

var template = `- CVSS Version {{ .Version }}
- Vector: {{ .Vector }}

## Base Metrics

- Base Score: {{ .BaseScore }}

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

## Temporal Metrics

- Temporal Score: {{ .TemporalScore }}
- {{ .SeverityName }}: {{ .SeverityValue }}

| {{ .TemporalMetrics }} | {{ .TemporalMetricValue }} |
|--------|-------|
| {{ .EName }} | {{ .EValue }} |
| {{ .RLName }} | {{ .RLValue }} |
| {{ .RCName }} | {{ .RCValue }} |
`

func main() {
	tm, err := metric.NewTemporal().Decode("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:F/RL:W/RC:R") //CVE-2020-1472: ZeroLogon
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	r, err := report.NewTemporal(tm).ExportWith(strings.NewReader(template))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if _, err := io.Copy(os.Stdout, r); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	// Output:
	// - CVSS Version 3.1
	// - Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:F/RL:W/RC:R
	//
	// ## Base Metrics
	//
	// - Base Score: 10
	//
	// | Base Metrics | Metric Value |
	// |--------|-------|
	// | Attack Vector | Network |
	// | Attack Complexity | Low |
	// | Privileges Required | None |
	// | User Interaction | None |
	// | Scope | Changed |
	// | Confidentiality Impact | High |
	// | Integrity Impact | High |
	// | Availability Impact | High |
	//
	// ## Temporal Metrics
	//
	// - Temporal Score: 9.1
	// - Severity: Critical
	//
	// | Temporal Metrics | Metric Value |
	// |--------|-------|
	// | Exploit Code Maturity | Functional |
	// | Remediation Level | Workaround |
	// | Report Confidence | Reasonable |
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
