# [go-cvss] - Common Vulnerability Scoring System (CVSS)

[![check vulns](https://github.com/goark/go-cvss/workflows/vulns/badge.svg)](https://github.com/goark/go-cvss/actions)
[![lint status](https://github.com/goark/go-cvss/workflows/lint/badge.svg)](https://github.com/goark/go-cvss/actions)
[![GitHub license](https://img.shields.io/badge/license-Apache%202-blue.svg)](https://raw.githubusercontent.com/goark/go-cvss/master/LICENSE)
[![GitHub release](https://img.shields.io/github/release/goark/go-cvss.svg)](https://github.com/goark/go-cvss/releases/latest)

Importing CVSS vector and scoring.

- Supports CVSS v2, v3.0 and v3.1
- Exporting CVSS information with template string

**Migrated repository to [github.com/goark/go-cvss][go-cvss]**

## Sample Code

### Base Metrics

```go
package main

import (
    "fmt"
    "os"

    "github.com/goark/go-cvss/v3/metric"
)

func main() {
    bm, err := metric.NewBase().Decode("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") //CVE-2020-1472: ZeroLogon
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

    "github.com/goark/go-cvss/v3/metric"
)

func main() {
    tm, err := metric.NewTemporal().Decode("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:F/RL:W/RC:R") //CVE-2020-1472: ZeroLogon
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

### Environmental Metrics

```go
package main

import (
	"fmt"
	"github.com/goark/go-cvss/v3/metric"
	"os"
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
```

### CVSSv2 Base Metrics

```go
package main

import (
	"fmt"
	"os"

	"github.com/goark/go-cvss/v2/metric"
)

func main() {
	bm, err := metric.NewBase().Decode("AV:N/AC:L/Au:N/C:N/I:N/A:C") //CVE-2002-0392
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Printf("Severity: %v (%v)\n", bm.Severity(), bm.Score())
	// Output:
	// Severity: Severity: High (7.8)
}
```

### CVSSv2 Temporal Metrics

```go
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
```

### CVSSv2 Environmental Metrics

```go
package main

import (
	"fmt"
	"os"

	"github.com/goark/go-cvss/v2/metric"
)

func main() {
	tm, err := metric.NewEnvironmental().Decode("AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:H") //CVE-2002-0392
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Printf("Severity (Base): %v (%v)\n", tm.Base.Severity(), tm.Base.Score())
	fmt.Printf("Severity (Temporal): %v (%v)\n", tm.Temporal.Severity(), tm.Temporal.Score())
	fmt.Printf("Severity (Environmental): %v (%v)\n", tm.Severity(), tm.Score())
	// Output:
	// Severity (Base): High (7.8)
	// Severity (Temporal): Medium (6.4)
	// Severity (Environmental): High (9.2)
}
```

### Reporting with template (CVSSv3 only)

ref: [sample.go](https://github.com/goark/go-cvss/blob/master/sample/sample.go)

## Reference

- [CVSS v2 Complete Documentation](https://www.first.org/cvss/v2/guide)
- [CVSS v3.0 Specification Document](https://www.first.org/cvss/v3.0/specification-document)
- [CVSS v3.1 Specification Document](https://www.first.org/cvss/v3.1/specification-document)

[go-cvss]: https://github.com/goark/go-cvss
