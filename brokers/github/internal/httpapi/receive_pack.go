package httpapi

import (
	"bytes"
	"io"

	"github.com/osolmaz/unyolo/brokers/github/internal/policy"
	"github.com/osolmaz/unyolo/git/protocol"
)

type receivePackCommand struct {
	OldOID string
	NewOID string
	Ref    string
}

type receivePackRequest struct {
	Commands []receivePackCommand
	Protocol gitx.ReceivePackRequest
	Pack     []byte
}

type authorizedReceivePackRequest struct {
	Request  policy.Request
	Decision policy.Decision
}

type requestableReceivePackRequest struct {
	Request  policy.Request
	Decision policy.Decision
}

func receivePackCommandsFromBody(body []byte) ([]receivePackCommand, error) {
	request, err := receivePackRequestFromBody(body)
	return request.Commands, err
}

func receivePackRequestFromBody(body []byte) (receivePackRequest, error) {
	reader := bytes.NewReader(body)
	parsed, err := gitx.ParseReceivePackRequest(reader)
	if err != nil {
		return receivePackRequest{}, err
	}
	pack, err := io.ReadAll(reader)
	if err != nil {
		return receivePackRequest{}, err
	}
	commands := make([]receivePackCommand, 0, len(parsed.Commands))
	for _, command := range parsed.Commands {
		commands = append(commands, receivePackCommand{OldOID: command.Old, NewOID: command.New, Ref: command.Ref})
	}
	return receivePackRequest{Commands: commands, Protocol: parsed, Pack: pack}, nil
}
