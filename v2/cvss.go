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

/* Copyright 2022 luxifer */
