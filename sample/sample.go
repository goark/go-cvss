//go:build run
// +build run

package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/goark/go-cvss/v3/metric"
	"github.com/goark/go-cvss/v3/report"
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

## Environmental Metrics

- {{ .SeverityName }}: {{ .SeverityValue }} ({{ .EnvironmentalScore }})

| {{ .EnvironmentalMetrics }} | {{ .EnvironmentalMetricValue }} |
|--------|-------|
| {{ .CRName }} | {{ .CRValue }} |
| {{ .IRName }} | {{ .IRValue }} |
| {{ .ARName }} | {{ .ARValue }} |
| {{ .MAVName }} | {{ .MAVValue }} |
| {{ .MACName }} | {{ .MACValue }} |
| {{ .MPRName }} | {{ .MPRValue }} |
| {{ .MUIName }} | {{ .MUIValue }} |
| {{ .MSName }}  | {{ .MSValue }} |
| {{ .MCName }}  | {{ .MCValue }} |
| {{ .MIName }}  | {{ .MIValue }} |
| {{ .MAName }}  | {{ .MAValue }} |
`

func main() {
	em, err := metric.NewEnvironmental().Decode("CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H/E:F/RL:U/RC:C/CR:M/IR:H/AR:M/MAV:L/MAC:H/MPR:L/MUI:R/MS:U/MC:L/MI:H/MA:L") //Random CVSS Vector
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	r, err := report.NewEnvironmental(em).ExportWith(strings.NewReader(template))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if _, err := io.Copy(os.Stdout, r); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	// Output:
	// - CVSS Version 3.1
	// - Vector: CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H/CR:M/IR:H/AR:M/MAV:L/MAC:H/MPR:L/MUI:R/MS:U/MC:L/MI:H/MA:L
	//
	// ## Base Metrics
	//
	// - Base Score: 6.1
	//
	// | Base Metrics | Metric Value |
	// |--------|-------|
	// | Attack Vector | Physical |
	// | Attack Complexity | High |
	// | Privileges Required | High |
	// | User Interaction | None |
	// | Scope | Unchanged |
	// | Confidentiality Impact | High |
	// | Integrity Impact | High |
	// | Availability Impact | High |
	//
	// ## Temporal Metrics
	//
	// - Temporal Score: 6
	// - Severity: Medium
	//
	// | Temporal Metrics | Metric Value |
	// |--------|-------|
	// | Exploit Code Maturity | Functional |
	// | Remediation Level | Unavailable |
	// | Report Confidence | Confirmed |
	//
	// ## Environmental Metrics
	//
	// - Severity: Medium (6.5)
	//
	// | Environmental Metrics | Metric Value |
	// |--------|-------|
	// | Confidentiality Requirement | Medium |
	// | Integrity Requirement | High |
	// | Availability Requirement | Medium |
	// | Modified Attack Vector | Local |
	// | Modified Attack Complexity | High |
	// | Modified Privileges Required | Low |
	// | Modified User Interaction | Required |
	// | Modified Scope  | Unchanged |
	// | Modified Confidentiality Impact  | Low |
	// | Modified Integrity Impact  | High |
	// | Modified Availability Impact  | Low |
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
