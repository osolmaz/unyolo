package operations

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/osolmaz/brokerkit/brokers/github/internal/githubauth"
	"github.com/osolmaz/brokerkit/internal/strictjson"
)

type planPreconditions struct {
	Credential githubauth.Metadata `json:"credential"`
	Operation  json.RawMessage     `json:"operation,omitempty"`
}

func credentialPreconditions(metadata githubauth.Metadata) json.RawMessage {
	return encodePreconditions(metadata, nil)
}

func encodePreconditions(metadata githubauth.Metadata, operation any) json.RawMessage {
	var raw json.RawMessage
	if operation != nil {
		raw, _ = json.Marshal(operation)
	}
	encoded, _ := json.Marshal(planPreconditions{Credential: metadata, Operation: raw})
	return encoded
}

// CredentialFromPreconditions restores the opaque credential selector bound
// into an immutable plan. It never contains a token or private key.
func CredentialFromPreconditions(raw json.RawMessage) (githubauth.Metadata, error) {
	preconditions, err := decodePreconditions(raw)
	if err != nil {
		return githubauth.Metadata{}, err
	}
	return preconditions.Credential, nil
}

func decodeOperationPreconditions(raw json.RawMessage, destination any) error {
	preconditions, err := decodePreconditions(raw)
	if err != nil {
		return err
	}
	if len(preconditions.Operation) == 0 || strictjson.Decode(preconditions.Operation, destination, true) != nil {
		return errors.New("GitHub operation preconditions are invalid")
	}
	return nil
}

func decodePreconditions(raw json.RawMessage) (planPreconditions, error) {
	var preconditions planPreconditions
	if err := strictjson.Decode(raw, &preconditions, true); err != nil {
		return planPreconditions{}, errors.New("GitHub credential preconditions are invalid")
	}
	if strings.TrimSpace(string(preconditions.Credential.Kind)) == "" {
		return planPreconditions{}, errors.New("GitHub credential preconditions are incomplete")
	}
	return preconditions, nil
}
