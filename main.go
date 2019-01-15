package main

import (
	"fmt"
	"os"

	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/apex/log"
	logcli "github.com/apex/log/handlers/cli"
	"github.com/jakewarren/suricata-rule-generator/generator"
)

func main() {
	o := generator.RuleOpts{}

	app := kingpin.New("suricata-rule-generator", "Generates suricata rules for IOCs.")

	app.Flag("sid", "Specify a sid value to use").Short('s').Default("xxxx").StringVar(&o.Sid)
	app.Flag("msg", "Specify a msg value to use").Short('m').StringVar(&o.Msg)
	app.Flag("classtype", "Specify a classtype value to use").Short('c').Default("trojan-activity").StringVar(&o.Classtype)
	app.Flag("metadata", "Add metadata values'").StringsVar(&o.Metadata)
	app.Flag("reference", "Add a reference value. Should be in the form of 'url,example.com' or 'md5,abc123'").Short('r').StringsVar(&o.References)

	dnsQuery := app.Command("dns-query", "Generate a signature for DNS queries")
	dnsQueryDomains := dnsQuery.Arg("domains", "contains the key value you want to generate the signature for").Required().Strings()

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
		for _, domain := range *dnsQueryDomains {
			rule, err := o.GenerateDNSQueryRule(domain)
			handleWarning(err)
			fmt.Println(rule)
		}
	}

}

func handleWarning(err error) {
	if err != nil {
		log.Warn(err.Error())
	}
}
