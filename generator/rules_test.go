package generator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)


func TestGetDefaultMetadata(t *testing.T) {
	defaultMetadata := getDefaultMetadata()

	assert.NotNil(t, defaultMetadata, "metadata not returned")

}
