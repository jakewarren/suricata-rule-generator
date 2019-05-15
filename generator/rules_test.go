package generator

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetDefaultMetadata(t *testing.T) {
	defaultMetadata := getDefaultMetadata()

	assert.NotNil(t, defaultMetadata, "metadata not returned")

}

// format the default metadata values to make them more friendly for tests
func formatDefaultMetadata() string {
	var sb strings.Builder
	md := getDefaultMetadata()

	for i, m := range md {
		if i < len(md)-1 {
			sb.WriteString(fmt.Sprintf("%s %s, ", m.Key, m.Value))
			continue
		}
		sb.WriteString(fmt.Sprintf("%s %s", m.Key, m.Value))
	}

	return sb.String()
}
