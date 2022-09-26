package v2

import "github.com/goark/go-cvss/v2/base"

// CVSS is type of CVSS
type CVSS struct {
	Base *base.Metrics
}

// New returns CVSS instance
func New() *CVSS {
	return &CVSS{Base: base.NewMetrics()}
}

// ImportBaseVector imports CVSSv2.0 base metrics vector
func (c *CVSS) ImportBaseVector(v string) error {
	m, err := base.Decode(v)
	if err != nil {
		return err
	}
	c.Base = m
	return nil
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
