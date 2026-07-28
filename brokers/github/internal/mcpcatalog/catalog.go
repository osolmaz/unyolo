// Package mcpcatalog filters typed GitHub MCP tools and pages discovery.
package mcpcatalog

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/osolmaz/unyolo/brokers/github/internal/mcpprojection"
	"github.com/osolmaz/unyolo/brokers/github/internal/opbinding"
	"github.com/osolmaz/unyolo/brokers/github/internal/opcatalog"
	ghpolicy "github.com/osolmaz/unyolo/brokers/github/internal/policy"
	"github.com/osolmaz/unyolo/brokers/github/internal/schemaregistry"
	"github.com/osolmaz/unyolo/operation/capability"
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
	tools := capability.MCPTools(capability.SurfaceOptions{Descriptors: opcatalog.CapabilityDescriptors(descriptors), Schemas: schemaregistry.InputSchemas,
		AttributeNames:         ghpolicy.CatalogAttributeNames(),
		WindowSubmitsOperation: true,
		MCPToolPrefix:          "gh_",
		Projections:            mcpprojection.ForOperation,
		ToolDescription: func(descriptor capability.Descriptor) string {
			return descriptor.Summary + " GitHub credentials remain inside GH Broker."
		}})
	for index, descriptor := range descriptors {
		bindings := opbinding.ByOperation(descriptor.Name)
		if len(bindings) == 1 && bindings[0].StreamDirection == "upload" {
			operation, _ := schemaregistry.ForOperation(descriptor.Name)
			schema := tools[index]["inputSchema"].(map[string]any)
			properties := schema["properties"].(map[string]any)
			properties["arguments"] = operation.Arguments
			properties["stream_input"] = streamReferenceSchema()
			required := schema["required"].([]string)
			schema["required"] = append(required, "stream_input")
		}
	}
	return tools, nil
}

func streamReferenceSchema() map[string]any {
	stringField := map[string]any{"type": "string", "minLength": 1, "maxLength": 255}
	return map[string]any{"type": "object", "additionalProperties": false,
		"required": []string{"id", "owner", "purpose", "transfer_id", "digest", "size", "media_type", "expires_at"},
		"properties": map[string]any{
			"id": stringField, "owner": stringField, "purpose": stringField, "transfer_id": stringField,
			"digest": map[string]any{"type": "string", "pattern": "^[a-f0-9]{64}$"}, "size": map[string]any{"type": "integer", "minimum": 1},
			"media_type": stringField, "expires_at": map[string]any{"type": "integer", "minimum": 1},
		}}
}

func Selected(exposure Exposure, enabled Enabled) ([]opcatalog.Descriptor, error) {
	values, err := opcatalog.All()
	if err != nil {
		return nil, err
	}
	exact, err := exactExposure(exposure.Exact)
	if err != nil {
		return nil, err
	}
	result := []opcatalog.Descriptor{}
	for _, descriptor := range values {
		if selectedDescriptor(descriptor, exposure, exact, enabled) {
			result = append(result, descriptor)
		}
	}
	return result, nil
}

func exactExposure(names []string) (map[string]bool, error) {
	exact := map[string]bool{}
	for _, name := range names {
		if _, found := opcatalog.ByName(name); !found {
			return nil, fmt.Errorf("unknown MCP exposure operation %q", name)
		}
		exact[name] = true
	}
	return exact, nil
}

func selectedDescriptor(descriptor opcatalog.Descriptor, exposure Exposure, exact map[string]bool, enabled Enabled) bool {
	if !descriptor.AgentFacing || !enabledForAll(descriptor.Name, enabled) {
		return false
	}
	return exact[descriptor.Name] || exposure.Complete || familyExposed(descriptor, exposure.Families)
}

func familyExposed(descriptor opcatalog.Descriptor, families []string) bool {
	if descriptor.ExplicitOnly {
		return false
	}
	for _, family := range families {
		if familyMatch(family, descriptor.Name) {
			return true
		}
	}
	return false
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
	offset, err := decodeCursor(cursor)
	if err != nil {
		return Page{}, err
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
	page.NextCursor = nextCursor(end, len(values))
	return page, nil
}

func decodeCursor(cursor string) (int, error) {
	if cursor == "" {
		return 0, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, errors.New("invalid discovery cursor")
	}
	offset, err := strconv.Atoi(string(data))
	if err != nil || offset < 0 {
		return 0, errors.New("invalid discovery cursor")
	}
	return offset, nil
}

func nextCursor(end, total int) string {
	if end >= total {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(end)))
}
