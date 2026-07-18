package main

import (
	"context"

	"github.com/osolmaz/brokerkit/mcpserver"
)

type mcpToolCall = mcpserver.ToolCall

func callMCPTool(ctx context.Context, client *agentClient, call mcpToolCall) (any, error) {
	bridge, err := newHFMCPBridge(client)
	if err != nil {
		return nil, err
	}
	return bridge.Call(ctx, call)
}
