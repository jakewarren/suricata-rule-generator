package generator

import (
	"fmt"
	"time"
)

//RuleOpts allow the user to add custom values to the generated rule
type RuleOpts struct {
	Sid        string
	Msg        string
	Classtype  string
	References []string
	Metadata   []string
}

func getDefaultMetadata() []string {
	t := time.Now()
	metadata := make([]string, 0)

	//add created date
	metadata = append(metadata, fmt.Sprintf("created_at %s", t.Format("2006_01_02")))

	//add last modified date
	metadata = append(metadata, fmt.Sprintf("updated_at %s", t.Format("2006_01_02")))

	return metadata
}
