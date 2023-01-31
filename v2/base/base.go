package base

import "github.com/goark/go-cvss/v2/metric"

// Metrics is Base Metrics for CVSSv2
//
// Deprecated: migrated github.com/goark/go-cvss/v2/metric package
type Metrics struct {
	*metric.Environmental
}

// NewMetrics returns Metrics instance
//
// Deprecated: migrated github.com/goark/go-cvss/v2/metric package
func NewMetrics() *Metrics {
	return &Metrics{metric.NewEnvironmental()}
}

// Decode returns Metrics instance by CVSSv2 vector
//
// Deprecated: migrated github.com/goark/go-cvss/v2/metric package
func Decode(vector string) (*Metrics, error) {
	m := NewMetrics()
	_, err := m.Decode(vector)
	return m, err
}

// Score returns score of Base metrics
//
// Deprecated: migrated github.com/goark/go-cvss/v2/metric package
func (m *Metrics) Score() float64 {
	return m.Base.Score()
}

// TemporalScore returns score of Temporal metrics
//
// Deprecated: migrated github.com/goark/go-cvss/v2/metric package
func (m *Metrics) TemporalScore() float64 {
	return m.Temporal.Score()
}

// EnvironmentalScore returns score of Environmental metrics
//
// Deprecated: migrated github.com/goark/go-cvss/v2/metric package
func (m *Metrics) EnvironmentalScore() float64 {
	return m.Environmental.Score()
}

// GetSeverity returns severity by score of Base metrics
//
// Deprecated: migrated github.com/goark/go-cvss/v2/metric package
func (m *Metrics) GetSeverity() Severity {
	return Severity(m.Base.GetSeverity())
}

/* Copyright 2022 luxifer */
/* Contributed by Spiegel, 2023 */
