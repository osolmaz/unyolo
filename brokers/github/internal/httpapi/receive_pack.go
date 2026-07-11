package httpapi

import (
	"bytes"

	"github.com/osolmaz/brokerkit/gitx"
	"github.com/osolmaz/brokerkit/brokers/github/internal/policy"
)

type receivePackCommand struct {
	OldOID string
	NewOID string
	Ref    string
}

type authorizedReceivePackRequest struct {
	Request  policy.Request
	Decision policy.Decision
}

func receivePackCommandsFromBody(body []byte) ([]receivePackCommand, error) {
	parsed, err := gitx.ParseReceivePackCommands(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	commands := make([]receivePackCommand, 0, len(parsed))
	for _, command := range parsed {
		commands = append(commands, receivePackCommand{OldOID: command.Old, NewOID: command.New, Ref: command.Ref})
	}
	return commands, nil
}
