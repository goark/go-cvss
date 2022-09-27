package base

import "strings"

//RemediationLevel is metric type for Temporal Metrics
type RemediationLevel int

//Constant of RemediationLevel result
const (
	RemediationLevelNotDefined RemediationLevel = iota
	RemediationLevelOfficialFix
	RemediationLevelTemporaryFix
	RemediationLevelWorkaround
	RemediationLevelUnavailable
)

var remediationLevelMap = map[RemediationLevel]string{
	RemediationLevelNotDefined:   "ND",
	RemediationLevelOfficialFix:  "OF",
	RemediationLevelTemporaryFix: "TF",
	RemediationLevelWorkaround:   "W",
	RemediationLevelUnavailable:  "U",
}

var remediationLevelValueMap = map[RemediationLevel]float64{
	RemediationLevelNotDefined:   1,
	RemediationLevelOfficialFix:  0.87,
	RemediationLevelTemporaryFix: 0.9,
	RemediationLevelWorkaround:   0.95,
	RemediationLevelUnavailable:  1,
}

//GetRemediationLevel returns result of RemediationLevel metric
func GetRemediationLevel(s string) RemediationLevel {
	s = strings.ToUpper(s)
	for k, v := range remediationLevelMap {
		if s == v {
			return k
		}
	}
	return RemediationLevelNotDefined
}

func (ai RemediationLevel) String() string {
	if s, ok := remediationLevelMap[ai]; ok {
		return s
	}
	return ""
}

//Value returns value of RemediationLevel metric
func (ai RemediationLevel) Value() float64 {
	if v, ok := remediationLevelValueMap[ai]; ok {
		return v
	}
	return 1
}

//IsDefined returns false if undefined result value of metric
func (ai RemediationLevel) IsDefined() bool {
	return ai != RemediationLevelNotDefined
}
