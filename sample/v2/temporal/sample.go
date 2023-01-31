//go:build run
// +build run

package main

import (
	"fmt"
	"os"

	"github.com/goark/go-cvss/v2/metric"
)

func main() {
	tm, err := metric.NewTemporal().Decode("AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C") //CVE-2002-0392
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Printf("Severity (Base): %v (%v)\n", tm.Base.Severity(), tm.Base.Score())
	fmt.Printf("Severity (Temporal): %v (%v)\n", tm.Severity(), tm.Score())
	// Output:
	// Severity (Base): High (7.8)
	// Severity (Temporal): Medium (6.4)
}

/* Copyright 2023 Spiegel
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
