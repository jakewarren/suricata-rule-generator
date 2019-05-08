package generator

import (
	"fmt"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/pkg/errors"
)

// GenerateDNSQueryRule generates a Suricata rule that alerts on a dns query for a domain
func (r RuleOpts) GenerateDNSQueryRule(domain string) (string, error) {
	var err error

	// check if the domain provided is a valid domain
	if !govalidator.IsURL(domain) {
		// record the error but not returning right away to give the user the benefit of the doubt
		err = errors.New("the provided value does not seem to be a domain")
	}

	// set a default msg if not provided
	if len(r.Msg) == 0 {
		r.Msg = fmt.Sprintf("DNS Query for %s", domain)
	}

	// process references
	references := ""
	for _, ref := range r.References {
		references = references + fmt.Sprintf("reference:%s; ", ref)
	}

	// process metadata
	metadata := "metadata:"
	metadata += strings.Join(getDefaultMetadata(), ", ")
	if len(r.Metadata) > 0 {
		metadata += ", "
		metadata += strings.Join(r.Metadata, ",")
	}
	metadata += "; "

	rule := fmt.Sprintf(`alert dns any any -> any any (msg:"%s"; dns_query; content:"%s"; nocase; %s%sclasstype:%s; sid:%s; rev:1;)`, r.Msg, domain, references, metadata, r.Classtype, r.Sid)

	return rule, err
}
