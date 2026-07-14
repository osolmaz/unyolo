// Package mcpprojection owns Hugging Face canonical-to-MCP field aliases.
package mcpprojection

import (
	"encoding/json"

	"github.com/osolmaz/brokerkit/capability"
)

var variableName = capability.MustProjection(capability.FieldProjection{Canonical: "/key", MCP: "/variable_name"})
var secretName = capability.MustProjection(capability.FieldProjection{Canonical: "/key", MCP: "/secret_name"})
var objectPath = capability.MustProjection(capability.FieldProjection{Canonical: "/key", MCP: "/object_path"})

func ForOperation(descriptor capability.Descriptor) capability.SurfaceProjection {
	projection := capability.SurfaceProjection{Attrs: objectPath}
	switch descriptor.Name {
	case "space.variable.set", "space.variable.delete":
		projection.Arguments = variableName
	case "space.secret.set", "space.secret.delete":
		projection.Arguments = secretName
	}
	return projection
}

func ArgumentsToCanonical(descriptor capability.Descriptor, raw json.RawMessage) (json.RawMessage, error) {
	projection := ForOperation(descriptor).Arguments
	if projection.Empty() {
		return raw, nil
	}
	return projection.ToCanonical(raw)
}

func AttrsToCanonical(descriptor capability.Descriptor, value map[string]any) (map[string]any, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	canonical, err := ForOperation(descriptor).Attrs.ToCanonical(raw)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(canonical, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func ResultToMCP(_ string, raw json.RawMessage) (json.RawMessage, error) { return raw, nil }
