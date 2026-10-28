package main

// organizationProjectItemReadback deliberately excludes user-owned projects,
// add/draft/view operations, and every other generic REST response.
func organizationProjectItemReadback(operation string) bool {
	switch operation {
	case "project.projects_list_items_for_org", "project.projects_get_org_item", "project.projects_update_item_for_org":
		return true
	default:
		return false
	}
}

// The pinned projects-v2-item-with-content schema leaves content and fields
// open. Closing it loses their properties; keeping them wholesale leaks unknown
// properties. These reviewed leaves come from its official example. This is
// intentionally option-identity readback, not an arbitrary field-value schema.
func projectItemResponseSchema(operation string, schema map[string]any) map[string]any {
	if !organizationProjectItemReadback(operation) {
		return schema
	}
	item := schema
	if schema["type"] == "array" {
		item = schema["items"].(map[string]any)
	}
	properties := item["properties"].(map[string]any)
	text := func() map[string]any { return map[string]any{"type": "string", "maxLength": 4096} }
	object := func(properties map[string]any) map[string]any {
		return map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	}
	properties["content"] = object(map[string]any{
		"id": map[string]any{"type": "number"}, "node_id": text(),
		"number": map[string]any{"type": "integer"}, "url": text(), "html_url": text(),
	})
	// Other official example field values contain object/array identities too.
	// Preserve only these explicit leaves, never body/HTML/user/repository blobs.
	value := object(map[string]any{
		"id":   map[string]any{"type": []string{"string", "number"}, "maxLength": 4096},
		"name": object(map[string]any{"raw": text()}),
	})
	properties["fields"] = map[string]any{
		"type": "array", "maxItems": 100,
		"items": object(map[string]any{
			"id": map[string]any{"type": "integer"}, "name": text(), "data_type": text(),
			"value": map[string]any{"anyOf": []any{value, map[string]any{"type": "array", "maxItems": 100, "items": value}}},
		}),
	}
	return schema
}

func projectItemResponseProjection() []string {
	return []string{
		"content.html_url", "content.id", "content.node_id", "content.number", "content.url",
		"content_type", "created_at", "fields.data_type", "fields.id", "fields.name",
		"fields.value.id", "fields.value.name.raw", "id", "node_id", "updated_at",
	}
}
