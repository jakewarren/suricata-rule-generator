package generator

import (
	"time"

	"github.com/google/gonids"
)

//RuleOpts allow the user to add custom values to the generated rule
type RuleOpts struct {
	Sid        int
	Msg        string
	Classtype  string
	References []string
	Metadata   []string
}

func getDefaultMetadata() gonids.Metadatas {
	t := time.Now()
	metadata := make([]*gonids.Metadata, 0)

	//add created date
	metadata = append(metadata, &gonids.Metadata{Key: "created_at", Value: t.Format("2006_01_02")})

	//add last modified date
	metadata = append(metadata, &gonids.Metadata{Key: "updated_at", Value: t.Format("2006_01_02")})

	return metadata
}
