package main

import (
	"fmt"
	"os"

	cvss "github.com/spiegel-im-spiegel/go-cvss"
)

func main() {
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
