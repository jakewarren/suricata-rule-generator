package generator

import (
	"fmt"
	"sort"
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

	// To store the keys in slice in sorted order
	var keys []string
	for k := range md {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	i := -1
	for _, k := range keys {
		i++
		if i < len(keys)-1 {
			sb.WriteString(fmt.Sprintf("%s %s, ", k, md[k]))
			continue
		}
		sb.WriteString(fmt.Sprintf("%s %s", k, md[k]))

	}

	return sb.String()
}
