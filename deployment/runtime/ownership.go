package runtime

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"

	"github.com/osolmaz/brokerkit/deployment/api"
	"github.com/osolmaz/brokerkit/internal/host/bundle"
)

// ValidateOwnership rejects adapter claims outside its signed envelope.
func ValidateOwnership(response api.Response, component bundle.Component) error {
	if component.Setup == nil {
		return errors.New("component has no setup ownership envelope")
	}
	for _, action := range response.Actions {
		if err := validateResource(action.Resource, component.Setup.Ownership); err != nil {
			return errors.New("setup-component action exceeds signed ownership envelope")
		}
	}
	return nil
}

//nolint:cyclop // Signed ownership is an exhaustive closed resource-kind switch.
func validateResource(resource api.Resource, envelope bundle.OwnershipEnvelope) error {
	switch resource.Kind {
	case "file", "directory", "socket", "client", "git_config":
		if resource.Path == "" || !ownedPath(resource.Path, envelope.Paths) {
			return errors.New("path is not owned")
		}
	case "service":
		if !slices.Contains(envelope.Services, resource.ID) {
			return errors.New("service is not owned")
		}
	case "account":
		if !slices.Contains(envelope.Accounts, resource.ID) {
			return errors.New("account is not owned")
		}
	case "group":
		if !slices.Contains(envelope.Groups, resource.ID) {
			return errors.New("group is not owned")
		}
	case "credential":
		if strings.TrimSpace(resource.ID) == "" {
			return errors.New("credential identity is empty")
		}
	default:
		return errors.New("resource kind is unsupported")
	}
	return nil
}

func ownedPath(path string, prefixes []string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	for _, prefix := range prefixes {
		if path == prefix || strings.HasPrefix(path, prefix+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
