# [go-cvss] - Common Vulnerability Scoring System (CVSS) Version 3

[![check vulns](https://github.com/spiegel-im-spiegel/go-cvss/workflows/vulns/badge.svg)](https://github.com/spiegel-im-spiegel/go-cvss/actions)
[![lint status](https://github.com/spiegel-im-spiegel/go-cvss/workflows/lint/badge.svg)](https://github.com/spiegel-im-spiegel/go-cvss/actions)
[![GitHub license](https://img.shields.io/badge/license-Apache%202-blue.svg)](https://raw.githubusercontent.com/spiegel-im-spiegel/go-cvss/master/LICENSE)
[![GitHub release](https://img.shields.io/github/release/spiegel-im-spiegel/go-cvss.svg)](https://github.com/spiegel-im-spiegel/go-cvss/releases/latest)

## Sample Code

ref: [sample.go](https://github.com/spiegel-im-spiegel/go-cvss/blob/master/sample/sample.go)

### Base Metrics

```go
package main

import (
    "fmt"
    "os"

    cvss "github.com/spiegel-im-spiegel/go-cvss"
)

func main() {
    bm, err := cvss.ImportV3Base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") //CVE-2020-1472: ZeroLogon
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        return
    }
    fmt.Printf("Severity: %v (%v)\n", bm.Severity(), bm.Score())
    // Output:
    // Severity: Critical (10)
}
```

### Temporal Metrics

```go
package main

import (
    "fmt"
    "os"

    cvss "github.com/spiegel-im-spiegel/go-cvss"
)

func main() {
    tm, err := cvss.ImportV3Temporal("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:F/RL:W/RC:R") //CVE-2020-1472: ZeroLogon
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
```

## Bookmark

- [CVSS v3.0 Specification Document](https://www.first.org/cvss/v3.0/specification-document)
- [CVSS v3.1 Specification Document](https://www.first.org/cvss/v3.1/specification-document)
- [JVN が CVSSv3 による脆弱性評価を開始 — しっぽのさきっちょ | text.Baldanders.info](http://text.baldanders.info/remark/2015/cvss-v3-metrics-in-jvn/)

[go-cvss]: https://github.com/spiegel-im-spiegel/cvss3
