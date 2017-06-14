package generator

import (
	"errors"
	"fmt"

	"github.com/asaskevich/govalidator"
)

//RuleOpts allow the user to add custom values to the generated rule
type RuleOpts struct {
	Sid        string
	Msg        string
	Classtype  string
	References []string
}

//GenerateDNSQueryRule generates a Suricata rule that alerts on a dns query for a domain
func (r RuleOpts) GenerateDNSQueryRule(domain string) (string, error) {
	var err error

	//check if the domain provided is a valid domain
	if !govalidator.IsURL(domain) {
		err = errors.New("the provided value does not seem to be a domain")
	}

	//set a default msg if not provided
	if len(r.Msg) == 0 {
		r.Msg = fmt.Sprintf("DNS Query for %s", domain)
	}

	//process references
	references := ""
	for _, ref := range r.References {
		references = references + fmt.Sprintf("reference:%s; ", ref)
	}

	rule := fmt.Sprintf(`alert dns any any -> any any (msg:"%s"; dns_query; content:"%s"; nocase; %sclasstype:%s; sid:%s; rev:1;)`, r.Msg, domain, references, r.Classtype, r.Sid)

	return rule, err
}
