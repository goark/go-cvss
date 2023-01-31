package metric

// Severity is severity for Base Metrics
type Severity int

// Constant of severity
const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
)

var severityMap = map[Severity]string{
	SeverityLow:    "Low",
	SeverityMedium: "Medium",
	SeverityHigh:   "High",
}

func (sv Severity) String() string {
	if s, ok := severityMap[sv]; ok {
		return s
	}
	return "Unknown"
}

// GetSeverity returns severity by score of Base metrics
func severity(score float64) Severity {
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

/* Copyright 2018-2023 Spiegel
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
