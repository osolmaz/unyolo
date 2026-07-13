// Package mcpcatalog filters typed GitHub MCP tools and pages discovery.
package mcpcatalog

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/schemaregistry"
	"github.com/osolmaz/brokerkit/capability"
)

type Exposure struct {
	Exact    []string
	Families []string
	Complete bool
}

type Enabled struct {
	Client  map[string]bool
	Policy  map[string]bool
	Runtime map[string]bool
}

type Page struct {
	Items      []opcatalog.Descriptor `json:"items"`
	NextCursor string                 `json:"next_cursor,omitempty"`
	Total      int                    `json:"total"`
}

var defaultExact = []string{"repo.metadata.read", "repo.contents.read", "pull_request.create", "pull_request.update"}

func DefaultExposure() Exposure { return Exposure{Exact: append([]string(nil), defaultExact...)} }

func Tools(exposure Exposure, enabled Enabled) ([]map[string]any, error) {
	descriptors, err := Selected(exposure, enabled)
	if err != nil {
		return nil, err
	}
	return capability.MCPTools(capability.SurfaceOptions{Descriptors: opcatalog.CapabilityDescriptors(descriptors), Schemas: schemaregistry.InputSchemas,
		AttributeNames: []string{"actor_id", "actor_login", "base_ref", "environment", "head_ref", "label", "merge_method", "path", "permission", "ref", "release_state", "resource_id", "role", "visibility", "workflow", "workflow_ref"},
		ToolDescription: func(descriptor capability.Descriptor) string {
			return descriptor.Summary + " GitHub credentials remain inside GH Broker."
		}}), nil
}

//nolint:cyclop // The four-way exposure intersection is kept explicit and fail-closed.
func Selected(exposure Exposure, enabled Enabled) ([]opcatalog.Descriptor, error) {
	values, err := opcatalog.All()
	if err != nil {
		return nil, err
	}
	exact := map[string]bool{}
	for _, name := range exposure.Exact {
		if _, found := opcatalog.ByName(name); !found {
			return nil, fmt.Errorf("unknown MCP exposure operation %q", name)
		}
		exact[name] = true
	}
	result := []opcatalog.Descriptor{}
	for _, descriptor := range values {
		if !descriptor.AgentFacing || !enabledForAll(descriptor.Name, enabled) {
			continue
		}
		exposed := exact[descriptor.Name] || exposure.Complete
		if !exposed && !descriptor.ExplicitOnly {
			for _, family := range exposure.Families {
				if familyMatch(family, descriptor.Name) {
					exposed = true
					break
				}
			}
		}
		if exposed {
			result = append(result, descriptor)
		}
	}
	return result, nil
}

func enabledForAll(name string, enabled Enabled) bool {
	return enabled.Client[name] && enabled.Policy[name] && enabled.Runtime[name]
}

func familyMatch(family, name string) bool {
	family = strings.TrimSuffix(strings.TrimSpace(family), ".*")
	return family != "" && strings.HasPrefix(name, family+".")
}

func Discover(cursor string, limit int) (Page, error) {
	if limit <= 0 || limit > 100 {
		return Page{}, errors.New("discovery page size must be between 1 and 100")
	}
	offset := 0
	if cursor != "" {
		data, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil {
			return Page{}, errors.New("invalid discovery cursor")
		}
		offset, err = strconv.Atoi(string(data))
		if err != nil || offset < 0 {
			return Page{}, errors.New("invalid discovery cursor")
		}
	}
	values, err := opcatalog.All()
	if err != nil {
		return Page{}, err
	}
	if offset > len(values) {
		return Page{}, errors.New("discovery cursor is out of range")
	}
	end := min(offset+limit, len(values))
	page := Page{Items: values[offset:end], Total: len(values)}
	if end < len(values) {
		page.NextCursor = base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(end)))
	}
	return page, nil
}
