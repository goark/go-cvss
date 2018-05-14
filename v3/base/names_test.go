package base

import (
	"testing"

	"golang.org/x/text/language"
)

func TestBaseName(t *testing.T) {
	testCases := []struct {
		lang language.Tag
		n    string
	}{
		{lang: language.Und, n: "Base Metrics"},
		{lang: language.English, n: "Base Metrics"},
		{lang: language.Japanese, n: "基本評価基準"},
	}
	for _, tc := range testCases {
		n := (&Metrics{}).Name(tc.lang)
		if n != tc.n {
			t.Errorf("Metrics.Name(%v) = \"%v\", want \"%v\".", tc.lang, n, tc.n)
		}
	}
}

func TestAttackVectorName(t *testing.T) {
	testCases := []struct {
		lang language.Tag
		av   AttackVector
		n    string
		nv   string
	}{
		{lang: language.Und, av: AttackVectorUnknown, n: "Attack Vector", nv: "Unknown"},
		{lang: language.English, av: AttackVectorUnknown, n: "Attack Vector", nv: "Unknown"},
		{lang: language.Japanese, av: AttackVectorUnknown, n: "攻撃元区分", nv: "不明"},

		{lang: language.Und, av: AttackVectorPhysical, n: "Attack Vector", nv: "Physical"},
		{lang: language.English, av: AttackVectorPhysical, n: "Attack Vector", nv: "Physical"},
		{lang: language.Japanese, av: AttackVectorPhysical, n: "攻撃元区分", nv: "物理"},

		{lang: language.Und, av: AttackVectorLocal, n: "Attack Vector", nv: "Local"},
		{lang: language.English, av: AttackVectorLocal, n: "Attack Vector", nv: "Local"},
		{lang: language.Japanese, av: AttackVectorLocal, n: "攻撃元区分", nv: "ローカル"},

		{lang: language.Und, av: AttackVectorAdjacent, n: "Attack Vector", nv: "Adjacent"},
		{lang: language.English, av: AttackVectorAdjacent, n: "Attack Vector", nv: "Adjacent"},
		{lang: language.Japanese, av: AttackVectorAdjacent, n: "攻撃元区分", nv: "隣接"},

		{lang: language.Und, av: AttackVectorNetwork, n: "Attack Vector", nv: "Network"},
		{lang: language.English, av: AttackVectorNetwork, n: "Attack Vector", nv: "Network"},
		{lang: language.Japanese, av: AttackVectorNetwork, n: "攻撃元区分", nv: "ネットワーク"},
	}
	for _, tc := range testCases {
		n := tc.av.Name(tc.lang)
		if n != tc.n {
			t.Errorf("AttackVector.Name(%v) = \"%v\", want \"%v\".", tc.lang, n, tc.n)
		}
		nv := tc.av.NameOfValue(tc.lang)
		if nv != tc.nv {
			t.Errorf("AttackVector.NameOfValue(%v) = \"%v\", want \"%v\".", tc.lang, nv, tc.nv)
		}
	}
}

func TestAttackComplexityName(t *testing.T) {
	testCases := []struct {
		lang language.Tag
		ac   AttackComplexity
		n    string
		nv   string
	}{
		{lang: language.Und, ac: AttackComplexityUnknown, n: "Attack Complexity", nv: "Unknown"},
		{lang: language.English, ac: AttackComplexityUnknown, n: "Attack Complexity", nv: "Unknown"},
		{lang: language.Japanese, ac: AttackComplexityUnknown, n: "攻撃条件の複雑さ", nv: "不明"},

		{lang: language.Und, ac: AttackComplexityHigh, n: "Attack Complexity", nv: "High"},
		{lang: language.English, ac: AttackComplexityHigh, n: "Attack Complexity", nv: "High"},
		{lang: language.Japanese, ac: AttackComplexityHigh, n: "攻撃条件の複雑さ", nv: "高"},

		{lang: language.Und, ac: AttackComplexityLow, n: "Attack Complexity", nv: "Low"},
		{lang: language.English, ac: AttackComplexityLow, n: "Attack Complexity", nv: "Low"},
		{lang: language.Japanese, ac: AttackComplexityLow, n: "攻撃条件の複雑さ", nv: "低"},
	}
	for _, tc := range testCases {
		n := tc.ac.Name(tc.lang)
		if n != tc.n {
			t.Errorf("AttackComplexity.Name(%v) = \"%v\", want \"%v\".", tc.lang, n, tc.n)
		}
		nv := tc.ac.NameOfValue(tc.lang)
		if nv != tc.nv {
			t.Errorf("AttackComplexity.NameOfValue(%v) = \"%v\", want \"%v\".", tc.lang, nv, tc.nv)
		}
	}
}

func TestPrivilegesRequiredName(t *testing.T) {
	testCases := []struct {
		lang language.Tag
		pr   PrivilegesRequired
		n    string
		nv   string
	}{
		{lang: language.Und, pr: PrivilegesRequiredUnknown, n: "Privileges Required", nv: "Unknown"},
		{lang: language.English, pr: PrivilegesRequiredUnknown, n: "Privileges Required", nv: "Unknown"},
		{lang: language.Japanese, pr: PrivilegesRequiredUnknown, n: "必要な特権レベル", nv: "不明"},

		{lang: language.Und, pr: PrivilegesRequiredHigh, n: "Privileges Required", nv: "High"},
		{lang: language.English, pr: PrivilegesRequiredHigh, n: "Privileges Required", nv: "High"},
		{lang: language.Japanese, pr: PrivilegesRequiredHigh, n: "必要な特権レベル", nv: "高"},

		{lang: language.Und, pr: PrivilegesRequiredLow, n: "Privileges Required", nv: "Low"},
		{lang: language.English, pr: PrivilegesRequiredLow, n: "Privileges Required", nv: "Low"},
		{lang: language.Japanese, pr: PrivilegesRequiredLow, n: "必要な特権レベル", nv: "低"},

		{lang: language.Und, pr: PrivilegesRequiredNone, n: "Privileges Required", nv: "None"},
		{lang: language.English, pr: PrivilegesRequiredNone, n: "Privileges Required", nv: "None"},
		{lang: language.Japanese, pr: PrivilegesRequiredNone, n: "必要な特権レベル", nv: "不要"},
	}
	for _, tc := range testCases {
		n := tc.pr.Name(tc.lang)
		if n != tc.n {
			t.Errorf("PrivilegesRequired.Name(%v) = \"%v\", want \"%v\".", tc.lang, n, tc.n)
		}
		nv := tc.pr.NameOfValue(tc.lang)
		if nv != tc.nv {
			t.Errorf("PrivilegesRequired.NameOfValue(%v) = \"%v\", want \"%v\".", tc.lang, nv, tc.nv)
		}
	}
}

func TestUserInteractionName(t *testing.T) {
	testCases := []struct {
		lang language.Tag
		ui   UserInteraction
		n    string
		nv   string
	}{
		{lang: language.Und, ui: UserInteractionUnknown, n: "User Interaction", nv: "Unknown"},
		{lang: language.English, ui: UserInteractionUnknown, n: "User Interaction", nv: "Unknown"},
		{lang: language.Japanese, ui: UserInteractionUnknown, n: "ユーザ関与レベル", nv: "不明"},

		{lang: language.Und, ui: UserInteractionRequired, n: "User Interaction", nv: "Required"},
		{lang: language.English, ui: UserInteractionRequired, n: "User Interaction", nv: "Required"},
		{lang: language.Japanese, ui: UserInteractionRequired, n: "ユーザ関与レベル", nv: "要"},

		{lang: language.Und, ui: UserInteractionNone, n: "User Interaction", nv: "None"},
		{lang: language.English, ui: UserInteractionNone, n: "User Interaction", nv: "None"},
		{lang: language.Japanese, ui: UserInteractionNone, n: "ユーザ関与レベル", nv: "不要"},
	}
	for _, tc := range testCases {
		n := tc.ui.Name(tc.lang)
		if n != tc.n {
			t.Errorf("UserInteraction.Name(%v) = \"%v\", want \"%v\".", tc.lang, n, tc.n)
		}
		nv := tc.ui.NameOfValue(tc.lang)
		if nv != tc.nv {
			t.Errorf("UserInteraction.NameOfValue(%v) = \"%v\", want \"%v\".", tc.lang, nv, tc.nv)
		}
	}
}

func TestScopeName(t *testing.T) {
	testCases := []struct {
		lang language.Tag
		s    Scope
		n    string
		nv   string
	}{
		{lang: language.Und, s: ScopeUnknown, n: "Scope", nv: "Unknown"},
		{lang: language.English, s: ScopeUnknown, n: "Scope", nv: "Unknown"},
		{lang: language.Japanese, s: ScopeUnknown, n: "スコープ", nv: "不明"},

		{lang: language.Und, s: ScopeUnchanged, n: "Scope", nv: "Unchanged"},
		{lang: language.English, s: ScopeUnchanged, n: "Scope", nv: "Unchanged"},
		{lang: language.Japanese, s: ScopeUnchanged, n: "スコープ", nv: "変更なし"},

		{lang: language.Und, s: ScopeChanged, n: "Scope", nv: "Changed"},
		{lang: language.English, s: ScopeChanged, n: "Scope", nv: "Changed"},
		{lang: language.Japanese, s: ScopeChanged, n: "スコープ", nv: "変更あり"},
	}
	for _, tc := range testCases {
		n := tc.s.Name(tc.lang)
		if n != tc.n {
			t.Errorf("UserInteraction.Name(%v) = \"%v\", want \"%v\".", tc.lang, n, tc.n)
		}
		nv := tc.s.NameOfValue(tc.lang)
		if nv != tc.nv {
			t.Errorf("UserInteraction.NameOfValue(%v) = \"%v\", want \"%v\".", tc.lang, nv, tc.nv)
		}
	}
}

func TestConfidentialityImpactName(t *testing.T) {
	testCases := []struct {
		lang language.Tag
		c    ConfidentialityImpact
		n    string
		nv   string
	}{
		{lang: language.Und, c: ConfidentialityImpactUnknown, n: "Confidentiality Impact", nv: "Unknown"},
		{lang: language.English, c: ConfidentialityImpactUnknown, n: "Confidentiality Impact", nv: "Unknown"},
		{lang: language.Japanese, c: ConfidentialityImpactUnknown, n: "機密性への影響", nv: "不明"},

		{lang: language.Und, c: ConfidentialityImpactNone, n: "Confidentiality Impact", nv: "None"},
		{lang: language.English, c: ConfidentialityImpactNone, n: "Confidentiality Impact", nv: "None"},
		{lang: language.Japanese, c: ConfidentialityImpactNone, n: "機密性への影響", nv: "なし"},

		{lang: language.Und, c: ConfidentialityImpactLow, n: "Confidentiality Impact", nv: "Low"},
		{lang: language.English, c: ConfidentialityImpactLow, n: "Confidentiality Impact", nv: "Low"},
		{lang: language.Japanese, c: ConfidentialityImpactLow, n: "機密性への影響", nv: "低"},

		{lang: language.Und, c: ConfidentialityImpactHigh, n: "Confidentiality Impact", nv: "High"},
		{lang: language.English, c: ConfidentialityImpactHigh, n: "Confidentiality Impact", nv: "High"},
		{lang: language.Japanese, c: ConfidentialityImpactHigh, n: "機密性への影響", nv: "高"},
	}
	for _, tc := range testCases {
		n := tc.c.Name(tc.lang)
		if n != tc.n {
			t.Errorf("ConfidentialityImpact.Name(%v) = \"%v\", want \"%v\".", tc.lang, n, tc.n)
		}
		nv := tc.c.NameOfValue(tc.lang)
		if nv != tc.nv {
			t.Errorf("ConfidentialityImpact.NameOfValue(%v) = \"%v\", want \"%v\".", tc.lang, nv, tc.nv)
		}
	}
}

func TestIntegrityImpactName(t *testing.T) {
	testCases := []struct {
		lang language.Tag
		i    IntegrityImpact
		n    string
		nv   string
	}{
		{lang: language.Und, i: IntegrityImpactUnknown, n: "Integrity Impact", nv: "Unknown"},
		{lang: language.English, i: IntegrityImpactUnknown, n: "Integrity Impact", nv: "Unknown"},
		{lang: language.Japanese, i: IntegrityImpactUnknown, n: "完全性への影響", nv: "不明"},

		{lang: language.Und, i: IntegrityImpactNone, n: "Integrity Impact", nv: "None"},
		{lang: language.English, i: IntegrityImpactNone, n: "Integrity Impact", nv: "None"},
		{lang: language.Japanese, i: IntegrityImpactNone, n: "完全性への影響", nv: "なし"},

		{lang: language.Und, i: IntegrityImpactLow, n: "Integrity Impact", nv: "Low"},
		{lang: language.English, i: IntegrityImpactLow, n: "Integrity Impact", nv: "Low"},
		{lang: language.Japanese, i: IntegrityImpactLow, n: "完全性への影響", nv: "低"},

		{lang: language.Und, i: IntegrityImpactHigh, n: "Integrity Impact", nv: "High"},
		{lang: language.English, i: IntegrityImpactHigh, n: "Integrity Impact", nv: "High"},
		{lang: language.Japanese, i: IntegrityImpactHigh, n: "完全性への影響", nv: "高"},
	}
	for _, tc := range testCases {
		n := tc.i.Name(tc.lang)
		if n != tc.n {
			t.Errorf("IntegrityImpact.Name(%v) = \"%v\", want \"%v\".", tc.lang, n, tc.n)
		}
		nv := tc.i.NameOfValue(tc.lang)
		if nv != tc.nv {
			t.Errorf("IntegrityImpact.NameOfValue(%v) = \"%v\", want \"%v\".", tc.lang, nv, tc.nv)
		}
	}
}

func TestAvailabilityImpactName(t *testing.T) {
	testCases := []struct {
		lang language.Tag
		a    AvailabilityImpact
		n    string
		nv   string
	}{
		{lang: language.Und, a: AvailabilityImpactUnknown, n: "Availability Impact", nv: "Unknown"},
		{lang: language.English, a: AvailabilityImpactUnknown, n: "Availability Impact", nv: "Unknown"},
		{lang: language.Japanese, a: AvailabilityImpactUnknown, n: "可用性への影響", nv: "不明"},

		{lang: language.Und, a: AvailabilityImpactNone, n: "Availability Impact", nv: "None"},
		{lang: language.English, a: AvailabilityImpactNone, n: "Availability Impact", nv: "None"},
		{lang: language.Japanese, a: AvailabilityImpactNone, n: "可用性への影響", nv: "なし"},

		{lang: language.Und, a: AvailabilityImpactLow, n: "Availability Impact", nv: "Low"},
		{lang: language.English, a: AvailabilityImpactLow, n: "Availability Impact", nv: "Low"},
		{lang: language.Japanese, a: AvailabilityImpactLow, n: "可用性への影響", nv: "低"},

		{lang: language.Und, a: AvailabilityImpactHigh, n: "Availability Impact", nv: "High"},
		{lang: language.English, a: AvailabilityImpactHigh, n: "Availability Impact", nv: "High"},
		{lang: language.Japanese, a: AvailabilityImpactHigh, n: "可用性への影響", nv: "高"},
	}
	for _, tc := range testCases {
		n := tc.a.Name(tc.lang)
		if n != tc.n {
			t.Errorf("AvailabilityImpact.Name(%v) = \"%v\", want \"%v\".", tc.lang, n, tc.n)
		}
		nv := tc.a.NameOfValue(tc.lang)
		if nv != tc.nv {
			t.Errorf("AvailabilityImpact.NameOfValue(%v) = \"%v\", want \"%v\".", tc.lang, nv, tc.nv)
		}
	}
}

func TestSeverityName(t *testing.T) {
	testCases := []struct {
		lang language.Tag
		sv   Severity
		n    string
		nv   string
	}{
		{lang: language.Und, sv: SeverityUnknown, n: "Severity", nv: "Unknown"},
		{lang: language.English, sv: SeverityUnknown, n: "Severity", nv: "Unknown"},
		{lang: language.Japanese, sv: SeverityUnknown, n: "深刻度", nv: "不明"},

		{lang: language.Und, sv: SeverityNone, n: "Severity", nv: "None"},
		{lang: language.English, sv: SeverityNone, n: "Severity", nv: "None"},
		{lang: language.Japanese, sv: SeverityNone, n: "深刻度", nv: "なし"},

		{lang: language.Und, sv: SeverityLow, n: "Severity", nv: "Low"},
		{lang: language.English, sv: SeverityLow, n: "Severity", nv: "Low"},
		{lang: language.Japanese, sv: SeverityLow, n: "深刻度", nv: "注意"},

		{lang: language.Und, sv: SeverityMedium, n: "Severity", nv: "Medium"},
		{lang: language.English, sv: SeverityMedium, n: "Severity", nv: "Medium"},
		{lang: language.Japanese, sv: SeverityMedium, n: "深刻度", nv: "警告"},

		{lang: language.Und, sv: SeverityHigh, n: "Severity", nv: "High"},
		{lang: language.English, sv: SeverityHigh, n: "Severity", nv: "High"},
		{lang: language.Japanese, sv: SeverityHigh, n: "深刻度", nv: "重要"},

		{lang: language.Und, sv: SeverityCritical, n: "Severity", nv: "Critical"},
		{lang: language.English, sv: SeverityCritical, n: "Severity", nv: "Critical"},
		{lang: language.Japanese, sv: SeverityCritical, n: "深刻度", nv: "緊急"},
	}
	for _, tc := range testCases {
		n := tc.sv.Name(tc.lang)
		if n != tc.n {
			t.Errorf("Severity.Name(%v) = \"%v\", want \"%v\".", tc.lang, n, tc.n)
		}
		nv := tc.sv.NameOfValue(tc.lang)
		if nv != tc.nv {
			t.Errorf("Severity.NameOfValue(%v) = \"%v\", want \"%v\".", tc.lang, nv, tc.nv)
		}
	}
}

/* Copyright 2018 Spiegel
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
