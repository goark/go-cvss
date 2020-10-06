# [go-cvss] - Common Vulnerability Scoring System (CVSS) Version 3

[![check vulns](https://github.com/spiegel-im-spiegel/go-cvss/workflows/vulns/badge.svg)](https://github.com/spiegel-im-spiegel/go-cvss/actions)
[![lint status](https://github.com/spiegel-im-spiegel/go-cvss/workflows/lint/badge.svg)](https://github.com/spiegel-im-spiegel/go-cvss/actions)
[![GitHub license](https://img.shields.io/badge/license-Apache%202-blue.svg)](https://raw.githubusercontent.com/spiegel-im-spiegel/go-cvss/master/LICENSE)
[![GitHub release](https://img.shields.io/github/release/spiegel-im-spiegel/go-cvss.svg)](https://github.com/spiegel-im-spiegel/go-cvss/releases/latest)

### Sample Code

```go
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
		io.Copy(os.Stdout, r)
	}
}
```

ref: [sample.go](https://github.com/spiegel-im-spiegel/go-cvss/blob/master/sample/sample.go)

## Bookmark

- [CVSS v3.0 Specification Document](https://www.first.org/cvss/v3.0/specification-document)
- [CVSS v3.1 Specification Document](https://www.first.org/cvss/v3.1/specification-document)
- [JVN が CVSSv3 による脆弱性評価を開始 — しっぽのさきっちょ | text.Baldanders.info](http://text.baldanders.info/remark/2015/cvss-v3-metrics-in-jvn/)

[go-cvss]: https://github.com/spiegel-im-spiegel/cvss3
