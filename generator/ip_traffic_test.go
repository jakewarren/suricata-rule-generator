package generator

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateIPTrafficRule(t *testing.T) {

	// check that valid rules are created
	var validSigTests = []struct {
		n             int
		nets          []string
		expectedRules []string
	}{
		{
			1,
			[]string{"1.2.3.4"},
			[]string{
				fmt.Sprintf(`alert ip 1.2.3.4 any -> $HOME_NET any (msg:"Inbound Suspicious Activity"; metadata:%s; classtype:bad-unknown; sid:0; rev:1;)`, formatDefaultMetadata()),
				fmt.Sprintf(`alert ip $HOME_NET any -> 1.2.3.4 any (msg:"Outbound Suspicious Activity"; metadata:%s; classtype:bad-unknown; sid:0; rev:1;)`, formatDefaultMetadata()),
			},
		},
		{
			2,
			[]string{"1.2.3.4", "4.3.2.0/24"},
			[]string{
				fmt.Sprintf(`alert ip [1.2.3.4, 4.3.2.0/24] any -> $HOME_NET any (msg:"Inbound Suspicious Activity"; metadata:%s; classtype:bad-unknown; sid:0; rev:1;)`, formatDefaultMetadata()),
				fmt.Sprintf(`alert ip $HOME_NET any -> [1.2.3.4, 4.3.2.0/24] any (msg:"Outbound Suspicious Activity"; metadata:%s; classtype:bad-unknown; sid:0; rev:1;)`, formatDefaultMetadata()),
			},
		},
	}

	for _, tt := range validSigTests {
		testRuleInfo := RuleOpts{0, "", "bad-unknown", nil, nil}
		actualRules, err := testRuleInfo.GenerateIPTrafficRule(tt.nets)
		assert.Nil(t, err)
		for i := range actualRules {
			assert.Equal(t, tt.expectedRules[i], actualRules[i].String())
		}
	}
}
