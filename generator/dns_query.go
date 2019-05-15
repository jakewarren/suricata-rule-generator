package generator

import (
	"fmt"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/google/gonids"
	"github.com/pkg/errors"
)

// GenerateDNSQueryRule generates a Suricata rule that alerts on a dns query for a domain
func (r RuleOpts) GenerateDNSQueryRule(domain string) (gonids.Rule, error) {
	var (
		err  error
		rule gonids.Rule
	)

	// initialize the rule
	rule.Action = "alert"
	rule.Protocol = "dns"
	rule.Source = gonids.Network{
		Nets: []string{
			"any",
		},
		Ports: []string{
			"any",
		},
	}
	rule.Destination = gonids.Network{
		Nets: []string{
			"any",
		},
		Ports: []string{
			"any",
		},
	}

	// check if the domain provided is a valid domain
	if !govalidator.IsURL(domain) {
		// record the error but not returning right away to give the user the benefit of the doubt
		err = errors.New("the provided value does not seem to be a domain")
	}

	// set a default msg if not provided
	switch len(r.Msg) {
	case 0:
		rule.Description = fmt.Sprintf("DNS Query for %s", domain)
	default:
		rule.Description = r.Msg
	}

	// process references
	for _, ref := range r.References {
		t := strings.Split(ref, ",")[0]
		v := strings.Split(ref, ",")[1]
		rule.References = append(rule.References, &gonids.Reference{Type: t, Value: v})
	}

	// process metadata
	if len(r.Metadata) > 0 {
		for _, m := range r.Metadata {
			k := strings.Split(m, " ")[0]
			v := strings.Split(m, " ")[1]
			rule.Metas = append(rule.Metas, &gonids.Metadata{Key: k, Value: v})
		}
	} else {
		defaultMetadata := getDefaultMetadata()
		for k, v := range defaultMetadata {
			rule.Metas = append(rule.Metas, &gonids.Metadata{Key: k, Value: v})
		}
	}

	rule.Revision = 1
	rule.SID = r.Sid

	sb, _ := gonids.StickyBuffer("dns_query")

	rule.Contents = gonids.Contents{
		&gonids.Content{
			DataPosition: sb,
			Pattern:      []byte(domain),
			Options: []*gonids.ContentOption{
				{"nocase", ""},
			},
		},
	}

	rule.Tags = make(map[string]string)
	rule.Tags["classtype"] = r.Classtype

	return rule, err
}
