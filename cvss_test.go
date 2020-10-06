package cvss_test

import (
	"fmt"
	"os"

	"github.com/spiegel-im-spiegel/go-cvss"
)

func ExampleImportBase() {
	bm, err := cvss.ImportBase("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") //CVE-2020-1472: ZeroLogon
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Printf("Severity: %v (%v)\n", bm.Severity(), bm.Score())
	// Output:
	// Severity: Critical (10)
}

func ExampleImportTemporal() {
	tm, err := cvss.ImportTemporal("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:F/RL:W/RC:R") //CVE-2020-1472: ZeroLogon
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Printf("Base Severity: %v (%v)\n", tm.BaseMetrics().Severity(), tm.BaseMetrics().Score())
	fmt.Printf("Temporal Severity: %v (%v)\n", tm.Severity(), tm.Score())
	// Output:
	// Base Severity: Critical (10)
	// Temporal Severity: Critical (9.1)
}
