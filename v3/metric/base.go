package metric

import (
	"math"
	"strings"

	"github.com/goark/errs"
	"github.com/goark/go-cvss/cvsserr"
)

// Base is Base Metrics for CVSSv3
type Base struct {
	Ver   Version
	AV    AttackVector
	AC    AttackComplexity
	PR    PrivilegesRequired
	UI    UserInteraction
	S     Scope
	C     ConfidentialityImpact
	I     IntegrityImpact
	A     AvailabilityImpact
	names map[string]bool
}

// NewBase returns Base Metrics instance
func NewBase() *Base {
	return &Base{
		Ver:   VUnknown,
		AV:    AttackVectorUnknown,
		AC:    AttackComplexityUnknown,
		PR:    PrivilegesRequiredUnknown,
		UI:    UserInteractionUnknown,
		S:     ScopeUnknown,
		C:     ConfidentialityImpactUnknown,
		I:     IntegrityImpactUnknown,
		A:     AvailabilityImpactUnknown,
		names: map[string]bool{},
	}
}

func (bm *Base) Decode(vector string) (*Base, error) {
	if bm == nil {
		bm = NewBase()
	}
	values := strings.Split(vector, "/")
	if len(values) < 9 {
		return bm, errs.Wrap(cvsserr.ErrInvalidVector, errs.WithContext("vector", vector))
	}
	//CVSS version
	ver, err := GetVersion(values[0])
	if err != nil {
		return bm, errs.Wrap(err, errs.WithContext("vector", vector))
	}
	if ver == VUnknown {
		return bm, errs.Wrap(cvsserr.ErrNotSupportVer, errs.WithContext("vector", vector))
	}
	bm.Ver = ver
	//parse vector
	var lastErr error
	for _, value := range values[1:] {
		if err := bm.decodeOne(value); err != nil {
			if !errs.Is(err, cvsserr.ErrNotSupportMetric) {
				return nil, errs.Wrap(err, errs.WithContext("vector", vector))
			}
			lastErr = err
		}
	}
	if lastErr != nil {
		return bm, lastErr
	}
	return bm, bm.GetError()
}
func (bm *Base) decodeOne(str string) error {
	m := strings.Split(str, ":")
	if len(m) != 2 || len(m[0]) == 0 || len(m[1]) == 0 {
		return errs.Wrap(cvsserr.ErrInvalidVector, errs.WithContext("metric", str))
	}
	name := m[0]
	if bm.names[name] {
		return errs.Wrap(cvsserr.ErrSameMetric, errs.WithContext("metric", str))
	}
	switch name {
	case "AV": //Attack Vector
		bm.AV = GetAttackVector(m[1])
		if bm.AV == AttackVectorUnknown {
			return errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", str))
		}
	case "AC": //Attack Complexity
		bm.AC = GetAttackComplexity(m[1])
		if bm.AC == AttackComplexityUnknown {
			return errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", str))
		}
	case "PR": //Privileges Required
		bm.PR = GetPrivilegesRequired(m[1])
		if bm.PR == PrivilegesRequiredUnknown {
			return errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", str))
		}
	case "UI": //User Interaction
		bm.UI = GetUserInteraction(m[1])
		if bm.UI == UserInteractionUnknown {
			return errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", str))
		}
	case "S": //Scope
		bm.S = GetScope(m[1])
		if bm.S == ScopeUnknown {
			return errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", str))
		}
	case "C": //Confidentiality Impact
		bm.C = GetConfidentialityImpact(m[1])
		if bm.C == ConfidentialityImpactUnknown {
			return errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", str))
		}
	case "I": //Integrity Impact
		bm.I = GetIntegrityImpact(m[1])
		if bm.I == IntegrityImpactUnknown {
			return errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", str))
		}
	case "A": //Availability Impact
		bm.A = GetAvailabilityImpact(m[1])
		if bm.A == AvailabilityImpactUnknown {
			return errs.Wrap(cvsserr.ErrInvalidValue, errs.WithContext("metric", str))
		}
	default:
		return errs.Wrap(cvsserr.ErrNotSupportMetric, errs.WithContext("metric", str))
	}
	bm.names[name] = true
	return nil
}

// GetError returns error instance if undefined metric
func (bm *Base) GetError() error {
	if bm == nil {
		return errs.Wrap(cvsserr.ErrUndefinedMetric)
	}
	switch true {
	case bm.Ver == VUnknown, bm.AV.IsUnknown(), bm.AC.IsUnknown(), bm.PR.IsUnknown(), bm.UI.IsUnknown(), bm.S.IsUnknown(), bm.C.IsUnknown(), bm.I.IsUnknown(), bm.A.IsUnknown():
		return errs.Wrap(cvsserr.ErrUndefinedMetric)
	default:
		return nil
	}
}

// Encode returns CVSSv3 vector string
func (bm *Base) Encode() (string, error) {
	if err := bm.GetError(); err != nil {
		return "", err
	}
	r := &strings.Builder{}
	r.WriteString("CVSS:" + bm.Ver.String()) //CVSS Version
	r.WriteString("/AV:" + bm.AV.String())   //Attack Vector
	r.WriteString("/AC:" + bm.AC.String())   //Attack Complexity
	r.WriteString("/PR:" + bm.PR.String())   //Privileges Required
	r.WriteString("/UI:" + bm.UI.String())   //User Interaction
	r.WriteString("/S:" + bm.S.String())     //Scope
	r.WriteString("/C:" + bm.C.String())     //Confidentiality Impact
	r.WriteString("/I:" + bm.I.String())     //Integrity Impact
	r.WriteString("/A:" + bm.A.String())     //Availability Impact
	return r.String(), nil
}

// String is stringer method.
func (bm *Base) String() string {
	s, _ := bm.Encode()
	return s
}

// Score returns score of Base metrics
func (bm *Base) Score() float64 {
	if err := bm.GetError(); err != nil {
		return 0.0
	}

	impact := 1.0 - (1-bm.C.Value())*(1-bm.I.Value())*(1-bm.A.Value())
	if bm.S == ScopeUnchanged {
		impact *= 6.42
	} else {
		impact = 7.52*(impact-0.029) - 3.25*math.Pow(impact-0.02, 15.0)
	}
	ease := 8.22 * bm.AV.Value() * bm.AC.Value() * bm.PR.Value(bm.S) * bm.UI.Value()

	var score float64
	if impact <= 0 {
		score = 0.0
	} else if bm.S == ScopeUnchanged {
		score = roundUp(math.Min(impact+ease, 10))
	} else {
		score = roundUp(math.Min(1.08*(impact+ease), 10))
	}
	return score
}

// Severity returns severity by score of Base metrics
func (bm *Base) Severity() Severity {
	return severity(bm.Score())
}

type Metrics interface {
	// BaseMetrics returns the base type for any given metrics type.
	BaseMetrics() *Base
}

func (bm *Base) BaseMetrics() *Base {
	return bm
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
