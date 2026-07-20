package httpapi

import (
	"bytes"

	"github.com/osolmaz/brokerkit/brokers/github/internal/policy"
	"github.com/osolmaz/brokerkit/git/protocol"
)

type receivePackCommand struct {
	OldOID string
	NewOID string
	Ref    string
}

type receivePackRequest struct {
	Commands []receivePackCommand
	Protocol gitx.ReceivePackRequest
}

type authorizedReceivePackRequest struct {
	Request  policy.Request
	Decision policy.Decision
}

func receivePackCommandsFromBody(body []byte) ([]receivePackCommand, error) {
	request, err := receivePackRequestFromBody(body)
	return request.Commands, err
}

func receivePackRequestFromBody(body []byte) (receivePackRequest, error) {
	parsed, err := gitx.ParseReceivePackRequest(bytes.NewReader(body))
	if err != nil {
		return receivePackRequest{}, err
	}
	commands := make([]receivePackCommand, 0, len(parsed.Commands))
	for _, command := range parsed.Commands {
		commands = append(commands, receivePackCommand{OldOID: command.Old, NewOID: command.New, Ref: command.Ref})
	}
	return receivePackRequest{Commands: commands, Protocol: parsed}, nil
}
