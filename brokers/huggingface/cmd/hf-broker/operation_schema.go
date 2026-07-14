package main

import "github.com/osolmaz/brokerkit/capability"

func splitSealedArgumentsSchema(schema map[string]any, paths []string) (map[string]any, map[string]any) {
	return capability.SplitSealedArgumentsSchema(schema, paths)
}

func embeddedOperationSchema(schema map[string]any) map[string]any {
	return capability.EmbeddedOperationSchema(schema)
}

func requireSchemaPaths(schema map[string]any, paths []string) {
	capability.RequireSchemaPaths(schema, paths)
}
