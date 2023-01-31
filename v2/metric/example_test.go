package metric_test

import (
	"fmt"

	"github.com/goark/go-cvss/v2/metric"
)

func ExampleBase_Decode() {
	m, err := metric.NewBase().Decode("AV:N/AC:L/Au:N/C:N/I:N/A:C") //CVE-2002-0392
	if err != nil {
		return
	}
	fmt.Println("Score =", m.Score())
	fmt.Println("Severity =", m.Severity())
	//Output:
	//Score = 7.8
	//Severity = High
}

func ExampleTemporal_Decode() {
	m, err := metric.NewTemporal().Decode("AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C") //CVE-2002-0392
	if err != nil {
		return
	}
	fmt.Println("Score =", m.Score())
	fmt.Println("Severity =", m.Severity())
	//Output:
	//Score = 6.4
	//Severity = Medium
}

func ExampleEnvironmental_Decode() {
	m, err := metric.NewEnvironmental().Decode("AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:H") //CVE-2002-0392
	if err != nil {
		return
	}
	fmt.Println("Score =", m.Score())
	fmt.Println("Severity =", m.Severity())
	//Output:
	//Score = 9.2
	//Severity = High
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
