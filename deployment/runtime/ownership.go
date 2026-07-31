package runtime

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/osolmaz/unyolo/deployment/api"
	"github.com/osolmaz/unyolo/internal/host/bundle"
)

// ValidateOwnership rejects adapter claims outside its signed envelope.
func ValidateOwnership(response api.Response, component bundle.Component) error {
	return ValidateOwnershipWithPaths(response, component, nil)
}

// ValidateOwnershipWithPaths also accepts exact generated client paths bound to validated installation identities.
func ValidateOwnershipWithPaths(response api.Response, component bundle.Component, generatedClientPaths []string) error {
	if component.Setup == nil {
		return errors.New("component has no setup ownership envelope")
	}
	for _, action := range response.Actions {
		if err := validateResource(action.Resource, component.Setup.Ownership, generatedClientPaths); err != nil {
			return fmt.Errorf("setup-component action %s %q exceeds signed ownership envelope: %w", action.Resource.Kind, action.Resource.ID, err)
		}
	}
	return nil
}

//nolint:cyclop // Signed ownership is an exhaustive closed resource-kind switch.
func validateResource(resource api.Resource, envelope bundle.OwnershipEnvelope, generatedClientPaths []string) error {
	switch resource.Kind {
	case "client", "git_config":
		if resource.Path == "" || !OwnedPath(resource.Path, envelope.Paths) && !slices.Contains(generatedClientPaths, resource.Path) {
			return errors.New("generated client path is not bound to a selected identity")
		}
	case "file", "directory", "socket":
		if resource.Path == "" || !OwnedPath(resource.Path, envelope.Paths) {
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
	case "credential", "secret_store":
		if strings.TrimSpace(resource.ID) == "" || resource.Path == "" || !OwnedPath(resource.Path, envelope.Paths) {
			return errors.New("credential identity or path is not owned")
		}
	default:
		return errors.New("resource kind is unsupported")
	}
	return nil
}

// OwnedPath reports whether a clean absolute path belongs to an allowed prefix.
func OwnedPath(path string, prefixes []string) bool {
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
