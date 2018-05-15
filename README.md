# [go-cvss] - Common Vulnerability Scoring System (CVSS) Version 3

[![Build Status](https://travis-ci.org/spiegel-im-spiegel/go-cvss.svg?branch=master)](https://travis-ci.org/spiegel-im-spiegel/go-cvss)
[![GitHub license](https://img.shields.io/badge/license-Apache%202-blue.svg)](https://raw.githubusercontent.com/spiegel-im-spiegel/go-cvss/master/LICENSE)
[![GitHub release](http://img.shields.io/github/release/spiegel-im-spiegel/go-cvss.svg)](https://github.com/spiegel-im-spiegel/go-cvss/releases/latest)

## Install

```
$ go get -u github.com/spiegel-im-spiegel/gpgpdump
```

### Usage

```go
m := cvssv3.New()
if err := m.ImportBaseVector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"); err != nil {
    fmt.Fprintln(os.Stderr, err)
    return
}
severity := m.Base.GetSeverity()
fmt.Printf("%s: %v (%.1f)\n\n", severity.Title(language.English), severity, m.Base.Score())
if r, err := m.Base.Report(nil, language.English); err != nil { //output with CSV format
    fmt.Fprintln(os.Stderr, err)
} else {
    io.Copy(os.Stdout, r)
}
// Output:
//Severity: Critical (9.9)
//
//Base Metrics,Metric Value
//Attack Vector,Network
//Attack Complexity,Low
//Privileges Required,Low
//User Interaction,None
//Scope,Changed
//Confidentiality Impact,High
//Integrity Impact,High
//Availability Impact,High
```

ref: [sample.go](https://github.com/spiegel-im-spiegel/go-cvss/blob/master/sample/sample.go)

## Bookmark

- [CVSS v3.0 Specification Document](https://www.first.org/cvss/specification-document)
- [JVN が CVSSv3 による脆弱性評価を開始 — しっぽのさきっちょ | text.Baldanders.info](http://text.baldanders.info/remark/2015/cvss-v3-metrics-in-jvn/)

[go-cvss]: https://github.com/spiegel-im-spiegel/cvss3
