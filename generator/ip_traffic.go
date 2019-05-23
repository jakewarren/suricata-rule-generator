package generator

import (
	"strings"

	"github.com/google/gonids"
)

// GenerateIPTrafficRule generates Suricata rules that alerts on inbound/outbound traffic from a IP/CIDR
func (r RuleOpts) GenerateIPTrafficRule(nets []string) ([]gonids.Rule, error) {
	var (
		err  error
		rule gonids.Rule
	)

	// initialize the rule
	rule.Action = "alert"
	rule.Protocol = "ip"

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
		// use default metadata values
		rule.Metas = append(rule.Metas, getDefaultMetadata()...)
	}

	rule.Revision = 1
	rule.SID = r.Sid

	if len(r.Classtype) > 0 {
		rule.Tags = make(map[string]string)
		rule.Tags["classtype"] = r.Classtype
	}

	rules := make([]gonids.Rule, 2)

	// generate the inbound rule
	rule.Source = gonids.Network{
		Nets: nets,
		Ports: []string{
			"any",
		},
	}
	rule.Destination = gonids.Network{
		Nets: []string{
			"$HOME_NET",
		},
		Ports: []string{
			"any",
		},
	}
	// set a default msg if not provided
	switch len(r.Msg) {
	case 0:
		rule.Description = "Inbound Suspicious Activity"
	default:
		rule.Description = r.Msg
	}

	rules[0] = rule

	// generate the outbound rule
	rule.Source = gonids.Network{
		Nets: []string{
			"$HOME_NET",
		},
		Ports: []string{
			"any",
		},
	}
	rule.Destination = gonids.Network{
		Nets: nets,
		Ports: []string{
			"any",
		},
	}
	// set a default msg if not provided
	switch len(r.Msg) {
	case 0:
		rule.Description = "Outbound Suspicious Activity"
	default:
		rule.Description = r.Msg
	}

	rules[1] = rule

	return rules, err
}
