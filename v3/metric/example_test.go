package metric_test

import (
	"fmt"

	"github.com/goark/go-cvss/v3/metric"
)

func ExampleBase_Decode() {
	m, err := metric.NewBase().Decode("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") //CVE-2015-8252
	if err != nil {
		return
	}
	fmt.Println("Score =", m.Score())
	fmt.Println("Severity =", m.Severity())
	//Output:
	//Score = 7.5
	//Severity = High
}

func ExampleTemporal_Decode() {
	m, err := metric.NewTemporal().Decode("CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U")
	if err != nil {
		return
	}
	fmt.Println("Score =", m.Score())
	fmt.Println("Severity =", m.Severity())
	//Output:
	//Score = 5.9
	//Severity = Medium
}

func ExampleEnvironmental_Decode() {
	m, err := metric.NewEnvironmental().Decode("CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:L/E:P/RL:O/RC:U/CR:L/IR:M/AR:L/MAV:P/MAC:L/MPR:L/MUI:R/MS:C/MC:H/MI:H/MA:H")
	if err != nil {
		return
	}
	fmt.Println("Score =", m.Score())
	fmt.Println("Severity =", m.Severity())
	//Output:
	//Score = 5.5
	//Severity = Medium
}

/* Contributed by Florent Viel, 2020 */
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
