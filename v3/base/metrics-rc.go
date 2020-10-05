package base

import "strings"

//ReportConfidence is metric type for Temporal Metrics
type ReportConfidence int

//Constant of ReportConfidence result
const (
	ReportConfidenceNotDefined ReportConfidence = iota
	ReportConfidenceUnknown
	ReportConfidenceReasonable
	ReportConfidenceConfirmed
)

var ReportConfidenceMap = map[ReportConfidence]string{
	ReportConfidenceNotDefined: "X",
	ReportConfidenceUnknown:    "U",
	ReportConfidenceReasonable: "R",
	ReportConfidenceConfirmed:  "C",
}

var ReportConfidenceValueMap = map[ReportConfidence]float64{
	ReportConfidenceNotDefined: 1,
	ReportConfidenceUnknown:    0.92,
	ReportConfidenceReasonable: 0.96,
	ReportConfidenceConfirmed:  1,
}

//GetReportConfidence returns result of ReportConfidence metric
func GetReportConfidence(s string) ReportConfidence {
	s = strings.ToUpper(s)
	for k, v := range ReportConfidenceMap {
		if s == v {
			return k
		}
	}
	return ReportConfidenceNotDefined
}

func (ai ReportConfidence) String() string {
	if s, ok := ReportConfidenceMap[ai]; ok {
		return s
	}
	return ""
}

//Value returns value of ReportConfidence metric
func (ai ReportConfidence) Value() float64 {
	if v, ok := ReportConfidenceValueMap[ai]; ok {
		return v
	}
	return 1
}

//IsDefined returns false if undefined result value of metric
func (ai ReportConfidence) IsDefined() bool {
	return ai != ReportConfidenceNotDefined
}
