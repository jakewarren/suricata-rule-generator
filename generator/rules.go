package generator

import (
	"time"
)

//RuleOpts allow the user to add custom values to the generated rule
type RuleOpts struct {
	Sid        int
	Msg        string
	Classtype  string
	References []string
	Metadata   []string
}

func getDefaultMetadata() map[string]string {
	t := time.Now()
	metadata := make(map[string]string, 0)

	//add created date
	metadata["created_at"] = t.Format("2006_01_02")

	//add last modified date
	metadata["updated_at"] = t.Format("2006_01_02")

	return metadata
}
