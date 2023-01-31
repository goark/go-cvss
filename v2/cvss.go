package v2

import (
	"github.com/goark/go-cvss/v2/metric"
)

// CVSS is type of CVSS
type CVSS struct {
	Base *metric.Base
}

// New returns CVSS instance
func New() *CVSS {
	return &CVSS{metric.NewBase()}
}

// ImportBaseVector imports CVSSv2.0 base metrics vector
func (c *CVSS) ImportBaseVector(v string) error {
	m, err := c.Base.Decode(v)
	if err != nil {
		return err
	}
	c.Base = m
	return nil
}

/* Copyright 2022 luxifer */
/* Contributed by Spiegel, 2023 */
