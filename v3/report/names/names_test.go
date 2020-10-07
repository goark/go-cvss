package names

import (
	"testing"

	"github.com/spiegel-im-spiegel/go-cvss/v3/metric"
	"golang.org/x/text/language"
)

func TestBaseTitle(t *testing.T) {
	testCases := []struct {
		lang language.Tag
		n    string
		nv   string
	}{
		{lang: language.Und, n: "Base Metrics", nv: "Metric Value"},
		{lang: language.English, n: "Base Metrics", nv: "Metric Value"},
		{lang: language.Japanese, n: "基本評価基準", nv: "評価値"},
	}
	for _, tc := range testCases {
		n := BaseMetrics(tc.lang)
		if n != tc.n {
			t.Errorf("Metrics.Title(%v) = \"%v\", want \"%v\".", tc.lang, n, tc.n)
		}
		nv := BaseMetricsValueOf(tc.lang)
		if nv != tc.nv {
			t.Errorf("Metrics.NameOfvalue(%v) = \"%v\", want \"%v\".", tc.lang, nv, tc.nv)
		}
	}
}

func TestAttackVectorTitle(t *testing.T) {
	testCases := []struct {
		lang language.Tag
		av   metric.AttackVector
		n    string
		nv   string
	}{
		{lang: language.Und, av: metric.AttackVectorUnknown, n: "Attack Vector", nv: "Unknown"},
		{lang: language.English, av: metric.AttackVectorUnknown, n: "Attack Vector", nv: "Unknown"},
		{lang: language.Japanese, av: metric.AttackVectorUnknown, n: "攻撃元区分", nv: "未定義"},

		{lang: language.Und, av: metric.AttackVectorNotDefined, n: "Attack Vector", nv: "Not Defined"},
		{lang: language.English, av: metric.AttackVectorNotDefined, n: "Attack Vector", nv: "Not Defined"},
		{lang: language.Japanese, av: metric.AttackVectorNotDefined, n: "攻撃元区分", nv: "未評価"},

		{lang: language.Und, av: metric.AttackVectorPhysical, n: "Attack Vector", nv: "Physical"},
		{lang: language.English, av: metric.AttackVectorPhysical, n: "Attack Vector", nv: "Physical"},
		{lang: language.Japanese, av: metric.AttackVectorPhysical, n: "攻撃元区分", nv: "物理"},

		{lang: language.Und, av: metric.AttackVectorLocal, n: "Attack Vector", nv: "Local"},
		{lang: language.English, av: metric.AttackVectorLocal, n: "Attack Vector", nv: "Local"},
		{lang: language.Japanese, av: metric.AttackVectorLocal, n: "攻撃元区分", nv: "ローカル"},

		{lang: language.Und, av: metric.AttackVectorAdjacent, n: "Attack Vector", nv: "Adjacent"},
		{lang: language.English, av: metric.AttackVectorAdjacent, n: "Attack Vector", nv: "Adjacent"},
		{lang: language.Japanese, av: metric.AttackVectorAdjacent, n: "攻撃元区分", nv: "隣接"},

		{lang: language.Und, av: metric.AttackVectorNetwork, n: "Attack Vector", nv: "Network"},
		{lang: language.English, av: metric.AttackVectorNetwork, n: "Attack Vector", nv: "Network"},
		{lang: language.Japanese, av: metric.AttackVectorNetwork, n: "攻撃元区分", nv: "ネットワーク"},
	}
	for _, tc := range testCases {
		n := AttackVector(tc.lang)
		if n != tc.n {
			t.Errorf("AttackVector.Title(%v) = \"%v\", want \"%v\".", tc.lang, n, tc.n)
		}
		nv := AVValueOf(tc.av, tc.lang)
		if nv != tc.nv {
			t.Errorf("AttackVector.NameOfValue(%v) = \"%v\", want \"%v\".", tc.lang, nv, tc.nv)
		}
	}
}

func TestAttackComplexityTitle(t *testing.T) {
	testCases := []struct {
		lang language.Tag
		ac   metric.AttackComplexity
		n    string
		nv   string
	}{
		{lang: language.Und, ac: metric.AttackComplexityUnknown, n: "Attack Complexity", nv: "Unknown"},
		{lang: language.English, ac: metric.AttackComplexityUnknown, n: "Attack Complexity", nv: "Unknown"},
		{lang: language.Japanese, ac: metric.AttackComplexityUnknown, n: "攻撃条件の複雑さ", nv: "未定義"},

		{lang: language.Und, ac: metric.AttackComplexityNotDefined, n: "Attack Complexity", nv: "Not Defined"},
		{lang: language.English, ac: metric.AttackComplexityNotDefined, n: "Attack Complexity", nv: "Not Defined"},
		{lang: language.Japanese, ac: metric.AttackComplexityNotDefined, n: "攻撃条件の複雑さ", nv: "未評価"},

		{lang: language.Und, ac: metric.AttackComplexityHigh, n: "Attack Complexity", nv: "High"},
		{lang: language.English, ac: metric.AttackComplexityHigh, n: "Attack Complexity", nv: "High"},
		{lang: language.Japanese, ac: metric.AttackComplexityHigh, n: "攻撃条件の複雑さ", nv: "高"},

		{lang: language.Und, ac: metric.AttackComplexityLow, n: "Attack Complexity", nv: "Low"},
		{lang: language.English, ac: metric.AttackComplexityLow, n: "Attack Complexity", nv: "Low"},
		{lang: language.Japanese, ac: metric.AttackComplexityLow, n: "攻撃条件の複雑さ", nv: "低"},
	}
	for _, tc := range testCases {
		n := AttackComplexity(tc.lang)
		if n != tc.n {
			t.Errorf("AttackComplexity.Title(%v) = \"%v\", want \"%v\".", tc.lang, n, tc.n)
		}
		nv := ACValueOf(tc.ac, tc.lang)
		if nv != tc.nv {
			t.Errorf("AttackComplexity.NameOfValue(%v) = \"%v\", want \"%v\".", tc.lang, nv, tc.nv)
		}
	}
}

func TestPrivilegesRequiredTitle(t *testing.T) {
	testCases := []struct {
		lang language.Tag
		pr   metric.PrivilegesRequired
		n    string
		nv   string
	}{
		{lang: language.Und, pr: metric.PrivilegesRequiredUnknown, n: "Privileges Required", nv: "Unknown"},
		{lang: language.English, pr: metric.PrivilegesRequiredUnknown, n: "Privileges Required", nv: "Unknown"},
		{lang: language.Japanese, pr: metric.PrivilegesRequiredUnknown, n: "必要な特権レベル", nv: "未定義"},

		{lang: language.Und, pr: metric.PrivilegesRequiredNotDefined, n: "Privileges Required", nv: "Not Defined"},
		{lang: language.English, pr: metric.PrivilegesRequiredNotDefined, n: "Privileges Required", nv: "Not Defined"},
		{lang: language.Japanese, pr: metric.PrivilegesRequiredNotDefined, n: "必要な特権レベル", nv: "未評価"},

		{lang: language.Und, pr: metric.PrivilegesRequiredHigh, n: "Privileges Required", nv: "High"},
		{lang: language.English, pr: metric.PrivilegesRequiredHigh, n: "Privileges Required", nv: "High"},
		{lang: language.Japanese, pr: metric.PrivilegesRequiredHigh, n: "必要な特権レベル", nv: "高"},

		{lang: language.Und, pr: metric.PrivilegesRequiredLow, n: "Privileges Required", nv: "Low"},
		{lang: language.English, pr: metric.PrivilegesRequiredLow, n: "Privileges Required", nv: "Low"},
		{lang: language.Japanese, pr: metric.PrivilegesRequiredLow, n: "必要な特権レベル", nv: "低"},

		{lang: language.Und, pr: metric.PrivilegesRequiredNone, n: "Privileges Required", nv: "None"},
		{lang: language.English, pr: metric.PrivilegesRequiredNone, n: "Privileges Required", nv: "None"},
		{lang: language.Japanese, pr: metric.PrivilegesRequiredNone, n: "必要な特権レベル", nv: "不要"},
	}
	for _, tc := range testCases {
		n := PrivilegesRequired(tc.lang)
		if n != tc.n {
			t.Errorf("PrivilegesRequired.Title(%v) = \"%v\", want \"%v\".", tc.lang, n, tc.n)
		}
		nv := PRValueOf(tc.pr, tc.lang)
		if nv != tc.nv {
			t.Errorf("PrivilegesRequired.NameOfValue(%v) = \"%v\", want \"%v\".", tc.lang, nv, tc.nv)
		}
	}
}

func TestUserInteractionTitle(t *testing.T) {
	testCases := []struct {
		lang language.Tag
		ui   metric.UserInteraction
		n    string
		nv   string
	}{
		{lang: language.Und, ui: metric.UserInteractionUnknown, n: "User Interaction", nv: "Unknown"},
		{lang: language.English, ui: metric.UserInteractionUnknown, n: "User Interaction", nv: "Unknown"},
		{lang: language.Japanese, ui: metric.UserInteractionUnknown, n: "ユーザ関与レベル", nv: "未定義"},

		{lang: language.Und, ui: metric.UserInteractionNotDefined, n: "User Interaction", nv: "Not Defined"},
		{lang: language.English, ui: metric.UserInteractionNotDefined, n: "User Interaction", nv: "Not Defined"},
		{lang: language.Japanese, ui: metric.UserInteractionNotDefined, n: "ユーザ関与レベル", nv: "未評価"},

		{lang: language.Und, ui: metric.UserInteractionRequired, n: "User Interaction", nv: "Required"},
		{lang: language.English, ui: metric.UserInteractionRequired, n: "User Interaction", nv: "Required"},
		{lang: language.Japanese, ui: metric.UserInteractionRequired, n: "ユーザ関与レベル", nv: "要"},

		{lang: language.Und, ui: metric.UserInteractionNone, n: "User Interaction", nv: "None"},
		{lang: language.English, ui: metric.UserInteractionNone, n: "User Interaction", nv: "None"},
		{lang: language.Japanese, ui: metric.UserInteractionNone, n: "ユーザ関与レベル", nv: "不要"},
	}
	for _, tc := range testCases {
		n := UserInteraction(tc.lang)
		if n != tc.n {
			t.Errorf("UserInteraction.Title(%v) = \"%v\", want \"%v\".", tc.lang, n, tc.n)
		}
		nv := UIValueOf(tc.ui, tc.lang)
		if nv != tc.nv {
			t.Errorf("UserInteraction.NameOfValue(%v) = \"%v\", want \"%v\".", tc.lang, nv, tc.nv)
		}
	}
}

func TestScopeTitle(t *testing.T) {
	testCases := []struct {
		lang language.Tag
		s    metric.Scope
		n    string
		nv   string
	}{
		{lang: language.Und, s: metric.ScopeUnknown, n: "Scope", nv: "Unknown"},
		{lang: language.English, s: metric.ScopeUnknown, n: "Scope", nv: "Unknown"},
		{lang: language.Japanese, s: metric.ScopeUnknown, n: "スコープ", nv: "未定義"},

		{lang: language.Und, s: metric.ScopeNotDefined, n: "Scope", nv: "Not Defined"},
		{lang: language.English, s: metric.ScopeNotDefined, n: "Scope", nv: "Not Defined"},
		{lang: language.Japanese, s: metric.ScopeNotDefined, n: "スコープ", nv: "未評価"},

		{lang: language.Und, s: metric.ScopeUnchanged, n: "Scope", nv: "Unchanged"},
		{lang: language.English, s: metric.ScopeUnchanged, n: "Scope", nv: "Unchanged"},
		{lang: language.Japanese, s: metric.ScopeUnchanged, n: "スコープ", nv: "変更なし"},

		{lang: language.Und, s: metric.ScopeChanged, n: "Scope", nv: "Changed"},
		{lang: language.English, s: metric.ScopeChanged, n: "Scope", nv: "Changed"},
		{lang: language.Japanese, s: metric.ScopeChanged, n: "スコープ", nv: "変更あり"},
	}
	for _, tc := range testCases {
		n := Scope(tc.lang)
		if n != tc.n {
			t.Errorf("UserInteraction.Title(%v) = \"%v\", want \"%v\".", tc.lang, n, tc.n)
		}
		nv := SValueOf(tc.s, tc.lang)
		if nv != tc.nv {
			t.Errorf("UserInteraction.NameOfValue(%v) = \"%v\", want \"%v\".", tc.lang, nv, tc.nv)
		}
	}
}

func TestConfidentialityImpactTitle(t *testing.T) {
	testCases := []struct {
		lang language.Tag
		c    metric.ConfidentialityImpact
		n    string
		nv   string
	}{
		{lang: language.Und, c: metric.ConfidentialityImpactUnknown, n: "Confidentiality Impact", nv: "Unknown"},
		{lang: language.English, c: metric.ConfidentialityImpactUnknown, n: "Confidentiality Impact", nv: "Unknown"},
		{lang: language.Japanese, c: metric.ConfidentialityImpactUnknown, n: "機密性への影響", nv: "未定義"},

		{lang: language.Und, c: metric.ConfidentialityImpactNotDefined, n: "Confidentiality Impact", nv: "Not Defined"},
		{lang: language.English, c: metric.ConfidentialityImpactNotDefined, n: "Confidentiality Impact", nv: "Not Defined"},
		{lang: language.Japanese, c: metric.ConfidentialityImpactNotDefined, n: "機密性への影響", nv: "未評価"},

		{lang: language.Und, c: metric.ConfidentialityImpactNone, n: "Confidentiality Impact", nv: "None"},
		{lang: language.English, c: metric.ConfidentialityImpactNone, n: "Confidentiality Impact", nv: "None"},
		{lang: language.Japanese, c: metric.ConfidentialityImpactNone, n: "機密性への影響", nv: "なし"},

		{lang: language.Und, c: metric.ConfidentialityImpactLow, n: "Confidentiality Impact", nv: "Low"},
		{lang: language.English, c: metric.ConfidentialityImpactLow, n: "Confidentiality Impact", nv: "Low"},
		{lang: language.Japanese, c: metric.ConfidentialityImpactLow, n: "機密性への影響", nv: "低"},

		{lang: language.Und, c: metric.ConfidentialityImpactHigh, n: "Confidentiality Impact", nv: "High"},
		{lang: language.English, c: metric.ConfidentialityImpactHigh, n: "Confidentiality Impact", nv: "High"},
		{lang: language.Japanese, c: metric.ConfidentialityImpactHigh, n: "機密性への影響", nv: "高"},
	}
	for _, tc := range testCases {
		n := ConfidentialityImpact(tc.lang)
		if n != tc.n {
			t.Errorf("ConfidentialityImpact.Title(%v) = \"%v\", want \"%v\".", tc.lang, n, tc.n)
		}
		nv := CValueOf(tc.c, tc.lang)
		if nv != tc.nv {
			t.Errorf("ConfidentialityImpact.NameOfValue(%v) = \"%v\", want \"%v\".", tc.lang, nv, tc.nv)
		}
	}
}

func TestIntegrityImpactTitle(t *testing.T) {
	testCases := []struct {
		lang language.Tag
		i    metric.IntegrityImpact
		n    string
		nv   string
	}{
		{lang: language.Und, i: metric.IntegrityImpactUnknown, n: "Integrity Impact", nv: "Unknown"},
		{lang: language.English, i: metric.IntegrityImpactUnknown, n: "Integrity Impact", nv: "Unknown"},
		{lang: language.Japanese, i: metric.IntegrityImpactUnknown, n: "完全性への影響", nv: "未定義"},

		{lang: language.Und, i: metric.IntegrityImpactNotDefined, n: "Integrity Impact", nv: "Not Defined"},
		{lang: language.English, i: metric.IntegrityImpactNotDefined, n: "Integrity Impact", nv: "Not Defined"},
		{lang: language.Japanese, i: metric.IntegrityImpactNotDefined, n: "完全性への影響", nv: "未評価"},

		{lang: language.Und, i: metric.IntegrityImpactNone, n: "Integrity Impact", nv: "None"},
		{lang: language.English, i: metric.IntegrityImpactNone, n: "Integrity Impact", nv: "None"},
		{lang: language.Japanese, i: metric.IntegrityImpactNone, n: "完全性への影響", nv: "なし"},

		{lang: language.Und, i: metric.IntegrityImpactLow, n: "Integrity Impact", nv: "Low"},
		{lang: language.English, i: metric.IntegrityImpactLow, n: "Integrity Impact", nv: "Low"},
		{lang: language.Japanese, i: metric.IntegrityImpactLow, n: "完全性への影響", nv: "低"},

		{lang: language.Und, i: metric.IntegrityImpactHigh, n: "Integrity Impact", nv: "High"},
		{lang: language.English, i: metric.IntegrityImpactHigh, n: "Integrity Impact", nv: "High"},
		{lang: language.Japanese, i: metric.IntegrityImpactHigh, n: "完全性への影響", nv: "高"},
	}
	for _, tc := range testCases {
		n := IntegrityImpact(tc.lang)
		if n != tc.n {
			t.Errorf("IntegrityImpact.Title(%v) = \"%v\", want \"%v\".", tc.lang, n, tc.n)
		}
		nv := IValueOf(tc.i, tc.lang)
		if nv != tc.nv {
			t.Errorf("IntegrityImpact.NameOfValue(%v) = \"%v\", want \"%v\".", tc.lang, nv, tc.nv)
		}
	}
}

func TestAvailabilityImpactTitle(t *testing.T) {
	testCases := []struct {
		lang language.Tag
		a    metric.AvailabilityImpact
		n    string
		nv   string
	}{
		{lang: language.Und, a: metric.AvailabilityImpactUnknown, n: "Availability Impact", nv: "Unknown"},
		{lang: language.English, a: metric.AvailabilityImpactUnknown, n: "Availability Impact", nv: "Unknown"},
		{lang: language.Japanese, a: metric.AvailabilityImpactUnknown, n: "可用性への影響", nv: "未定義"},

		{lang: language.Und, a: metric.AvailabilityImpactNotDefined, n: "Availability Impact", nv: "Not Defined"},
		{lang: language.English, a: metric.AvailabilityImpactNotDefined, n: "Availability Impact", nv: "Not Defined"},
		{lang: language.Japanese, a: metric.AvailabilityImpactNotDefined, n: "可用性への影響", nv: "未評価"},

		{lang: language.Und, a: metric.AvailabilityImpactNone, n: "Availability Impact", nv: "None"},
		{lang: language.English, a: metric.AvailabilityImpactNone, n: "Availability Impact", nv: "None"},
		{lang: language.Japanese, a: metric.AvailabilityImpactNone, n: "可用性への影響", nv: "なし"},

		{lang: language.Und, a: metric.AvailabilityImpactLow, n: "Availability Impact", nv: "Low"},
		{lang: language.English, a: metric.AvailabilityImpactLow, n: "Availability Impact", nv: "Low"},
		{lang: language.Japanese, a: metric.AvailabilityImpactLow, n: "可用性への影響", nv: "低"},

		{lang: language.Und, a: metric.AvailabilityImpactHigh, n: "Availability Impact", nv: "High"},
		{lang: language.English, a: metric.AvailabilityImpactHigh, n: "Availability Impact", nv: "High"},
		{lang: language.Japanese, a: metric.AvailabilityImpactHigh, n: "可用性への影響", nv: "高"},
	}
	for _, tc := range testCases {
		n := AvailabilityImpact(tc.lang)
		if n != tc.n {
			t.Errorf("AvailabilityImpact.Title(%v) = \"%v\", want \"%v\".", tc.lang, n, tc.n)
		}
		nv := AValueOf(tc.a, tc.lang)
		if nv != tc.nv {
			t.Errorf("AvailabilityImpact.NameOfValue(%v) = \"%v\", want \"%v\".", tc.lang, nv, tc.nv)
		}
	}
}

func TestExploitabilityTitle(t *testing.T) {
	testCases := []struct {
		lang language.Tag
		v    metric.Exploitability
		n    string
		nv   string
	}{
		{lang: language.Und, v: metric.ExploitabilityNotDefined, n: "Exploit Code Maturity", nv: "Not Defined"},
		{lang: language.English, v: metric.ExploitabilityNotDefined, n: "Exploit Code Maturity", nv: "Not Defined"},
		{lang: language.Japanese, v: metric.ExploitabilityNotDefined, n: "攻撃される可能性", nv: "未評価"},

		{lang: language.Und, v: metric.ExploitabilityUnproven, n: "Exploit Code Maturity", nv: "Unproven"},
		{lang: language.English, v: metric.ExploitabilityUnproven, n: "Exploit Code Maturity", nv: "Unproven"},
		{lang: language.Japanese, v: metric.ExploitabilityUnproven, n: "攻撃される可能性", nv: "未実証"},

		{lang: language.Und, v: metric.ExploitabilityProofOfConcept, n: "Exploit Code Maturity", nv: "Proof-of-Concept"},
		{lang: language.English, v: metric.ExploitabilityProofOfConcept, n: "Exploit Code Maturity", nv: "Proof-of-Concept"},
		{lang: language.Japanese, v: metric.ExploitabilityProofOfConcept, n: "攻撃される可能性", nv: "実証可能"},

		{lang: language.Und, v: metric.ExploitabilityFunctional, n: "Exploit Code Maturity", nv: "Functional"},
		{lang: language.English, v: metric.ExploitabilityFunctional, n: "Exploit Code Maturity", nv: "Functional"},
		{lang: language.Japanese, v: metric.ExploitabilityFunctional, n: "攻撃される可能性", nv: "攻撃可能"},

		{lang: language.Und, v: metric.ExploitabilityHigh, n: "Exploit Code Maturity", nv: "High"},
		{lang: language.English, v: metric.ExploitabilityHigh, n: "Exploit Code Maturity", nv: "High"},
		{lang: language.Japanese, v: metric.ExploitabilityHigh, n: "攻撃される可能性", nv: "容易に攻撃可能"},
	}
	for _, tc := range testCases {
		n := Exploitability(tc.lang)
		if n != tc.n {
			t.Errorf("Exploitability.Title(%v) = \"%v\", want \"%v\".", tc.lang, n, tc.n)
		}
		nv := EValueOf(tc.v, tc.lang)
		if nv != tc.nv {
			t.Errorf("Exploitability.NameOfValue(%v) = \"%v\", want \"%v\".", tc.lang, nv, tc.nv)
		}
	}
}

func TestRemediationLevelTitle(t *testing.T) {
	testCases := []struct {
		lang language.Tag
		v    metric.RemediationLevel
		n    string
		nv   string
	}{
		{lang: language.Und, v: metric.RemediationLevelNotDefined, n: "Remediation Level", nv: "Not Defined"},
		{lang: language.English, v: metric.RemediationLevelNotDefined, n: "Remediation Level", nv: "Not Defined"},
		{lang: language.Japanese, v: metric.RemediationLevelNotDefined, n: "利用可能な対策のレベル", nv: "未評価"},

		{lang: language.Und, v: metric.RemediationLevelOfficialFix, n: "Remediation Level", nv: "Official Fix"},
		{lang: language.English, v: metric.RemediationLevelOfficialFix, n: "Remediation Level", nv: "Official Fix"},
		{lang: language.Japanese, v: metric.RemediationLevelOfficialFix, n: "利用可能な対策のレベル", nv: "正式"},

		{lang: language.Und, v: metric.RemediationLevelTemporaryFix, n: "Remediation Level", nv: "Temporary Fix"},
		{lang: language.English, v: metric.RemediationLevelTemporaryFix, n: "Remediation Level", nv: "Temporary Fix"},
		{lang: language.Japanese, v: metric.RemediationLevelTemporaryFix, n: "利用可能な対策のレベル", nv: "暫定"},

		{lang: language.Und, v: metric.RemediationLevelWorkaround, n: "Remediation Level", nv: "Workaround"},
		{lang: language.English, v: metric.RemediationLevelWorkaround, n: "Remediation Level", nv: "Workaround"},
		{lang: language.Japanese, v: metric.RemediationLevelWorkaround, n: "利用可能な対策のレベル", nv: "非公式"},

		{lang: language.Und, v: metric.RemediationLevelUnavailable, n: "Remediation Level", nv: "Unavailable"},
		{lang: language.English, v: metric.RemediationLevelUnavailable, n: "Remediation Level", nv: "Unavailable"},
		{lang: language.Japanese, v: metric.RemediationLevelUnavailable, n: "利用可能な対策のレベル", nv: "なし"},
	}
	for _, tc := range testCases {
		n := RemediationLevel(tc.lang)
		if n != tc.n {
			t.Errorf("RemediationLevel.Title(%v) = \"%v\", want \"%v\".", tc.lang, n, tc.n)
		}
		nv := RLValueOf(tc.v, tc.lang)
		if nv != tc.nv {
			t.Errorf("RemediationLevel.NameOfValue(%v) = \"%v\", want \"%v\".", tc.lang, nv, tc.nv)
		}
	}
}

func TestReportConfidenceTitle(t *testing.T) {
	testCases := []struct {
		lang language.Tag
		v    metric.ReportConfidence
		n    string
		nv   string
	}{
		{lang: language.Und, v: metric.ReportConfidenceNotDefined, n: "Report Confidence", nv: "Not Defined"},
		{lang: language.English, v: metric.ReportConfidenceNotDefined, n: "Report Confidence", nv: "Not Defined"},
		{lang: language.Japanese, v: metric.ReportConfidenceNotDefined, n: "脆弱性情報の信頼性", nv: "未評価"},

		{lang: language.Und, v: metric.ReportConfidenceUnknown, n: "Report Confidence", nv: "Unknown"},
		{lang: language.English, v: metric.ReportConfidenceUnknown, n: "Report Confidence", nv: "Unknown"},
		{lang: language.Japanese, v: metric.ReportConfidenceUnknown, n: "脆弱性情報の信頼性", nv: "未確認"},

		{lang: language.Und, v: metric.ReportConfidenceReasonable, n: "Report Confidence", nv: "Reasonable"},
		{lang: language.English, v: metric.ReportConfidenceReasonable, n: "Report Confidence", nv: "Reasonable"},
		{lang: language.Japanese, v: metric.ReportConfidenceReasonable, n: "脆弱性情報の信頼性", nv: "未確証"},

		{lang: language.Und, v: metric.ReportConfidenceConfirmed, n: "Report Confidence", nv: "Confirmed"},
		{lang: language.English, v: metric.ReportConfidenceConfirmed, n: "Report Confidence", nv: "Confirmed"},
		{lang: language.Japanese, v: metric.ReportConfidenceConfirmed, n: "脆弱性情報の信頼性", nv: "確認済"},
	}
	for _, tc := range testCases {
		n := ReportConfidence(tc.lang)
		if n != tc.n {
			t.Errorf("ReportConfidence.Title(%v) = \"%v\", want \"%v\".", tc.lang, n, tc.n)
		}
		nv := RCValueOf(tc.v, tc.lang)
		if nv != tc.nv {
			t.Errorf("ReportConfidence.NameOfValue(%v) = \"%v\", want \"%v\".", tc.lang, nv, tc.nv)
		}
	}
}

func TestSeverityTitle(t *testing.T) {
	testCases := []struct {
		lang language.Tag
		sv   metric.Severity
		n    string
		nv   string
	}{
		{lang: language.Und, sv: metric.SeverityUnknown, n: "Severity", nv: "Unknown"},
		{lang: language.English, sv: metric.SeverityUnknown, n: "Severity", nv: "Unknown"},
		{lang: language.Japanese, sv: metric.SeverityUnknown, n: "深刻度", nv: "未定義"},

		{lang: language.Und, sv: metric.SeverityNone, n: "Severity", nv: "None"},
		{lang: language.English, sv: metric.SeverityNone, n: "Severity", nv: "None"},
		{lang: language.Japanese, sv: metric.SeverityNone, n: "深刻度", nv: "なし"},

		{lang: language.Und, sv: metric.SeverityLow, n: "Severity", nv: "Low"},
		{lang: language.English, sv: metric.SeverityLow, n: "Severity", nv: "Low"},
		{lang: language.Japanese, sv: metric.SeverityLow, n: "深刻度", nv: "注意"},

		{lang: language.Und, sv: metric.SeverityMedium, n: "Severity", nv: "Medium"},
		{lang: language.English, sv: metric.SeverityMedium, n: "Severity", nv: "Medium"},
		{lang: language.Japanese, sv: metric.SeverityMedium, n: "深刻度", nv: "警告"},

		{lang: language.Und, sv: metric.SeverityHigh, n: "Severity", nv: "High"},
		{lang: language.English, sv: metric.SeverityHigh, n: "Severity", nv: "High"},
		{lang: language.Japanese, sv: metric.SeverityHigh, n: "深刻度", nv: "重要"},

		{lang: language.Und, sv: metric.SeverityCritical, n: "Severity", nv: "Critical"},
		{lang: language.English, sv: metric.SeverityCritical, n: "Severity", nv: "Critical"},
		{lang: language.Japanese, sv: metric.SeverityCritical, n: "深刻度", nv: "緊急"},
	}
	for _, tc := range testCases {
		n := Severity(tc.lang)
		if n != tc.n {
			t.Errorf("Severity.Title(%v) = \"%v\", want \"%v\".", tc.lang, n, tc.n)
		}
		nv := SeverityValueOf(tc.sv, tc.lang)
		if nv != tc.nv {
			t.Errorf("Severity.NameOfValue(%v) = \"%v\", want \"%v\".", tc.lang, nv, tc.nv)
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
