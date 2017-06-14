package generator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateDNSQueryRule(t *testing.T) {

	//check that valid rules are created
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

		assert.Equal(t, tt.expectedRule, actualRule)
		assert.Nil(t, err)
	}

	//test that a warning is generated with an invalid domain name
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

	//test that rule options are generated properly
	var ruleOptTests = []struct {
		n            int
		domain       string
		expectedRule string
	}{
		{1, "google.com", `alert dns any any -> any any (msg:"Test Msg"; dns_query; content:"google.com"; nocase; reference:url,google.com; reference:md5,abc1234; classtype:custom; sid:1234; rev:1;)`},
	}

	for _, tt := range ruleOptTests {
		testRuleInfo := RuleOpts{"1234", "Test Msg", "custom", []string{"url,google.com", "md5,abc1234"}}
		actualRule, err := testRuleInfo.GenerateDNSQueryRule(tt.domain)

		assert.Equal(t, tt.expectedRule, actualRule)
		assert.Nil(t, err)
	}

}
