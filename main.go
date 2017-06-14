package main

import (
	"fmt"
	"os"

	kingpin "gopkg.in/alecthomas/kingpin.v2"

	"github.com/apex/log"
	logcli "github.com/apex/log/handlers/cli"
	"github.com/jakewarren/suricata-rule-generator/generator"
)

var (
	app = kingpin.New("suricata-rule-generator", "Generates suricata rules for IOCs.")

	sid        = app.Flag("sid", "Specify a sid value to use").Short('s').Default("xxxx").String()
	msg        = app.Flag("msg", "Specify a msg value to use").Short('m').String()
	classtype  = app.Flag("classtype", "Specify a classtype value to use").Short('c').Default("trojan-activity").String()
	references = app.Flag("reference", "Add a reference value. Should be in the form of 'url,example.com' or 'md5,abc123'").Short('r').Strings()

	dnsQuery        = app.Command("dns-query", "Generate a signature for DNS queries")
	dnsQueryDomains = dnsQuery.Arg("domains", "contains the key value you want to generate the signature for").Required().Strings()
)

func main() {

	//set up logging
	log.SetLevel(log.DebugLevel)
	log.SetHandler(logcli.New(os.Stderr))

	//set up application information
	app.Version("0.1").VersionFlag.Short('V')
	app.HelpFlag.Short('h')
	app.UsageTemplate(kingpin.SeparateOptionalFlagsUsageTemplate)
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {

	//generate signatures for dns queries
	case dnsQuery.FullCommand():

		ri := readRuleOpts()
		for _, domain := range *dnsQueryDomains {
			rule, err := ri.GenerateDNSQueryRule(domain)
			if err != nil {
				log.Warn(err.Error())
			}
			fmt.Println(rule)

		}

	}

}

func readRuleOpts() generator.RuleOpts {
	var ri generator.RuleOpts

	//set the sid value, uses default value if user didn't provide one
	ri.Sid = *sid

	//set msg value if the user provided one
	if len(*msg) > 0 {
		ri.Msg = *msg
	}

	//set the classtype value, uses default value if user didn't provide one
	ri.Classtype = *classtype

	//set the references values
	ri.References = *references

	return ri
}
