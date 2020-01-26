package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	cvssv3 "github.com/spiegel-im-spiegel/go-cvss/v3"
	"golang.org/x/text/language"
)

func main() {
	tf := flag.String("t", "", "template file")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, os.ErrInvalid)
		return
	}
	vector := flag.Arg(0)
	var tr io.Reader
	if len(*tf) > 0 {
		file, err := os.Open(*tf)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		defer file.Close()
		tr = file
	}

	m := cvssv3.New()
	if err := m.ImportBaseVector(vector); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	severity := m.Base.GetSeverity()
	//lang := language.English
	lang := language.Japanese
	fmt.Printf("%s: %v (%.1f)\n\n", severity.Title(lang), severity.NameOfValue(lang), m.Base.Score())

	if r, err := m.Base.Report(tr, lang); err != nil {
		fmt.Fprintln(os.Stderr, err)
	} else {
		if _, err := io.Copy(os.Stdout, r); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
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
