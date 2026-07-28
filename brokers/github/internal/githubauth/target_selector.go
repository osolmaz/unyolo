package githubauth

import (
	"strings"

	"github.com/osolmaz/unyolo/brokers/github/internal/targetregistry"
)

func installationTargetID(target map[string]any) int64 {
	if id := int64Field(target, "installation_id"); id > 0 {
		return id
	}
	if strings.EqualFold(targetregistry.String(target, "kind"), "installation") {
		return int64Field(target, "id")
	}
	return 0
}
