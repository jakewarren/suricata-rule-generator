package generator

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateDNSQueryRule(t *testing.T) {

	// check that valid rules are created
	var validSigTests = []struct {
		n            int
		domain       string
		expectedRule string
	}{
		{1, "google.com", fmt.Sprintf(`alert dns any any -> any any (msg:"DNS Query for google.com"; dns_query; content:"google.com"; nocase; metadata:%s; classtype:trojan-activity; sid:xxxx; rev:1;)`, strings.Join(getDefaultMetadata(), ", "))},
		{2, "dash-test.com", fmt.Sprintf(`alert dns any any -> any any (msg:"DNS Query for dash-test.com"; dns_query; content:"dash-test.com"; nocase; metadata:%s; classtype:trojan-activity; sid:xxxx; rev:1;)`, strings.Join(getDefaultMetadata(), ", "))},
		{3, "subdomain.test.com", fmt.Sprintf(`alert dns any any -> any any (msg:"DNS Query for subdomain.test.com"; dns_query; content:"subdomain.test.com"; nocase; metadata:%s; classtype:trojan-activity; sid:xxxx; rev:1;)`, strings.Join(getDefaultMetadata(), ", "))},
	}

	for _, tt := range validSigTests {
		testRuleInfo := RuleOpts{"xxxx", "", "trojan-activity", nil, nil}
		actualRule, err := testRuleInfo.GenerateDNSQueryRule(tt.domain)

		assert.Equal(t, tt.expectedRule, actualRule)
		assert.Nil(t, err)
	}

	// test that a warning is generated with an invalid domain name
	var invalidSigTests = []struct {
		n            int
		domain       string
		expectedRule string
	}{
		{1, "google", ""},
	}

	for _, tt := range invalidSigTests {
		testRuleInfo := RuleOpts{"xxxx", "", "trojan-activity", nil, nil}
		_, err := testRuleInfo.GenerateDNSQueryRule(tt.domain)

		assert.NotNil(t, err, "a warning should have been generated")
	}

	// test that rule options are generated properly
	var ruleOptTests = []struct {
		n            int
		domain       string
		expectedRule string
	}{
		{1, "google.com", fmt.Sprintf(`alert dns any any -> any any (msg:"Test Msg"; dns_query; content:"google.com"; nocase; reference:url,google.com; reference:md5,abc1234; metadata:%s, tag test; classtype:custom; sid:1234; rev:1;)`, strings.Join(getDefaultMetadata(), ", "))},
	}

	for _, tt := range ruleOptTests {
		testRuleInfo := RuleOpts{"1234", "Test Msg", "custom", []string{"url,google.com", "md5,abc1234"}, []string{"tag test"}}
		actualRule, err := testRuleInfo.GenerateDNSQueryRule(tt.domain)

		assert.Equal(t, tt.expectedRule, actualRule)
		assert.Nil(t, err)
	}

}
