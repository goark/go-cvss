package base

import "strings"

//ReportConfidence is metric type for Temporal Metrics
type ReportConfidence int

//Constant of ReportConfidence result
const (
	ReportConfidenceNotDefined ReportConfidence = iota
	ReportConfidenceUnconfirmed
	ReportConfidenceUncorroborated
	ReportConfidenceConfirmed
)

var reportConfidenceMap = map[ReportConfidence]string{
	ReportConfidenceNotDefined:     "ND",
	ReportConfidenceUnconfirmed:    "UC",
	ReportConfidenceUncorroborated: "UR",
	ReportConfidenceConfirmed:      "C",
}

var reportConfidenceValueMap = map[ReportConfidence]float64{
	ReportConfidenceNotDefined:     1,
	ReportConfidenceUnconfirmed:    0.9,
	ReportConfidenceUncorroborated: 0.95,
	ReportConfidenceConfirmed:      1,
}

//GetReportConfidence returns result of ReportConfidence metric
func GetReportConfidence(s string) ReportConfidence {
	s = strings.ToUpper(s)
	for k, v := range reportConfidenceMap {
		if s == v {
			return k
		}
	}
	return ReportConfidenceNotDefined
}

func (ai ReportConfidence) String() string {
	if s, ok := reportConfidenceMap[ai]; ok {
		return s
	}
	return ""
}

//Value returns value of ReportConfidence metric
func (ai ReportConfidence) Value() float64 {
	if v, ok := reportConfidenceValueMap[ai]; ok {
		return v
	}
	return 1
}

//IsDefined returns false if undefined result value of metric
func (ai ReportConfidence) IsDefined() bool {
	return ai != ReportConfidenceNotDefined
}
