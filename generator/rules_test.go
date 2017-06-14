package generator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateDNSQueryRule(t *testing.T) {

	var validSigTests = []struct {
		n            int
		domain       string
		expectedRule string
	}{
		{1, "google.com", `alert dns any any -> any any (msg:"DNS Query for google.com"; dns_query; content:"google.com"; nocase; classtype:trojan-activity; sid:xxxx; rev:1;)`},
		{2, "dash-test.com", `alert dns any any -> any any (msg:"DNS Query for dash-test.com"; dns_query; content:"dash-test.com"; nocase; classtype:trojan-activity; sid:xxxx; rev:1;)`},
		{3, "subdomain.test.com", `alert dns any any -> any any (msg:"DNS Query for subdomain.test.com"; dns_query; content:"subdomain.test.com"; nocase; classtype:trojan-activity; sid:xxxx; rev:1;)`},
	}

	for _, tt := range validSigTests {
		testRuleInfo := RuleOpts{"xxxx", "", "trojan-activity", nil}
		actualRule, err := testRuleInfo.GenerateDNSQueryRule(tt.domain)

		assert.Equal(t, actualRule, tt.expectedRule)
		assert.Nil(t, err)
	}

	var invalidSigTests = []struct {
		n            int
		domain       string
		expectedRule string
	}{
		{1, "google", ""},
	}

	for _, tt := range invalidSigTests {
		testRuleInfo := RuleOpts{"xxxx", "", "trojan-activity", nil}
		_, err := testRuleInfo.GenerateDNSQueryRule(tt.domain)

		assert.NotNil(t, err, "a warning should have been generated")
	}

}
