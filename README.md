# suricata-rule-generator
[![Build Status](https://travis-ci.org/jakewarren/suricata-rule-generator.svg?branch=master)](https://travis-ci.org/jakewarren/suricata-rule-generator/)
[![GitHub release](http://img.shields.io/github/release/jakewarren/suricata-rule-generator.svg?style=flat-square)](https://github.com/jakewarren/suricata-rule-generator/releases])
[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](https://github.com/jakewarren/suricata-rule-generator/blob/master/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/jakewarren/suricata-rule-generator)](https://goreportcard.com/report/github.com/jakewarren/suricata-rule-generator)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=shields)](http://makeapullrequest.com)
> Generate suricata rules for IOCs
## Install
### Option 1: Binary

Download the latest release from [https://github.com/jakewarren/suricata-rule-generator/releases/latest](https://github.com/jakewarren/suricata-rule-generator/releases/latest)

### Option 2: From source

```
go get github.com/jakewarren/suricata-rule-generator
```

## Usage
### As a library
```golang
package main

import (
	"fmt"

	"github.com/jakewarren/suricata-rule-generator/generator"
)

func main() {
	o := generator.RuleOpts{}

	rule, _ := o.GenerateDNSQueryRule("github.com")
	fmt.Println(rule.String())
	//Output: alert dns any any -> any any (msg:"DNS Query for github.com"; dns_query; content:"github.com"; nocase; metadata:created_at 2019_05_15, updated_at 2019_05_15; sid:0; rev:1;)
}
```
### Using the command line tool

```
❯ suricata-rule-generator dns-query github.com
alert dns any any -> any any (msg:"DNS Query for github.com"; dns_query; content:"github.com"; nocase; metadata:created_at 2019_05_15, updated_at 2019_05_15; classtype:trojan-activity; sid:1234; rev:1;)
```

## License

MIT © 2019 Jake Warren

[changelog]: https://github.com/jakewarren/suricata-rule-generator/blob/master/CHANGELOG.md
