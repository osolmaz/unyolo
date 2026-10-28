package main

import "testing"

func assertFieldObjectsClosed(t *testing.T, value any) {
	t.Helper()
	switch node := value.(type) {
	case map[string]any:
		if node["type"] == "object" && node["additionalProperties"] != false {
			t.Errorf("open object: %v", node)
		}
		for _, child := range node {
			assertFieldObjectsClosed(t, child)
		}
	case []any:
		for _, child := range node {
			assertFieldObjectsClosed(t, child)
		}
	}
}
