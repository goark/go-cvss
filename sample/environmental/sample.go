//go:build run
// +build run

package main

import (
	"fmt"
	"os"

	"github.com/spiegel-im-spiegel/go-cvss/v3/metric"
)

func main() {
	em, err := metric.NewEnvironmental().Decode("CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H/E:F/RL:U/RC:C/CR:M/IR:H/AR:M/MAV:L/MAC:H/MPR:L/MUI:R/MS:U/MC:L/MI:H/MA:L") //Random CVSS Vector
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Printf("Base Severity: %v (%v)\n", em.BaseMetrics().Severity(), em.BaseMetrics().Score())
	fmt.Printf("Temporal Severity: %v (%v)\n", em.TemporalMetrics().Severity(), em.TemporalMetrics().Score())
	fmt.Printf("Environmental Severity: %v (%v)\n", em.Severity(), em.Score())
	// Output:
	// Base Severity: Critical (6.1)
	// Temporal Severity: Critical (6)
	// Environmental Severity: Critical (6.5)
}

/* Copyright 2022 thejohnbrown */
