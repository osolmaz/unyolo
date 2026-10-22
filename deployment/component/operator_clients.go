package component

import (
	"errors"
	"fmt"
	"os/user"
	"strconv"

	"github.com/osolmaz/unyolo/deployment/api"
	clientconfig "github.com/osolmaz/unyolo/internal/config/client"
)

const maxOperatorClients = 32

// validateOperatorClients checks that every operator client names a managed
// operator binding, an operator credential slot of this component, and a
// broker, and that each operator receives at most one document.
func validateOperatorClients(values []OperatorClient, operators []api.OperatorBinding, slots map[string]bool) error {
	if len(values) > maxOperatorClients {
		return errors.New("component deployment profile exceeds limits")
	}
	bound := map[string]bool{}
	for _, operator := range operators {
		bound[operator.ID] = true
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !bound[value.OperatorID] || !slots[value.SecretSlot] || value.Endpoint == "" || seen[value.OperatorID] {
			return errors.New("component operator client binding is invalid")
		}
		seen[value.OperatorID] = true
	}
	return nil
}

// inspectOperatorClients plans the operator client documents that are missing
// or no longer hold the operator's current credential.
func inspectOperatorClients(profile Profile, state *inspected) error {
	for _, client := range profile.OperatorClients {
		operator := state.operators[client.OperatorID]
		path, err := clientconfig.OperatorPath(operator.Home, client.BrokerName)
		if err != nil {
			return err
		}
		fingerprint := pathFingerprint(path)
		state.fingerprints = append(state.fingerprints, "operator-client:"+client.OperatorID+":"+client.BrokerName+":"+fingerprint)
		current := credentialAction(state.credentials, client.SecretSlot) == "retain" &&
			operatorClientCurrent(path, operator, client, state.storeSecrets[client.SecretSlot])
		if current {
			continue
		}
		state.actions = append(state.actions, api.PlannedAction{
			ID: operatorClientActionID(client), Type: "replace", Risk: "medium",
			Resource: api.Resource{Kind: "client", ID: "operator:" + client.OperatorID, Path: path}, CurrentState: resourceState(fingerprint),
			DesiredDigest: metadataDigest(0o600, operator.UnixUser, operator.UnixUser),
		})
	}
	return nil
}

func operatorClientActionID(client OperatorClient) string {
	return "operator-client-" + client.OperatorID
}

// applyOperatorClients writes each planned operator client document with the
// credential that the component installed or retained for its slot.
func applyOperatorClients(values []OperatorClient, operators map[string]api.OperatorBinding, secrets map[string][]byte) error {
	for _, value := range values {
		operator := operators[value.OperatorID]
		secret := secrets[value.SecretSlot]
		if len(secret) == 0 {
			return fmt.Errorf("operator client %q credential is unavailable", value.OperatorID)
		}
		if _, err := clientconfig.WriteOperatorForHomeOwner(operator.Home, value.BrokerName, clientconfig.Operator{
			Endpoint: value.Endpoint, Secret: string(secret),
		}); err != nil {
			return fmt.Errorf("write operator client %q: %w", value.OperatorID, err)
		}
	}
	return nil
}

// verifyOperatorClients confirms that each operator client document holds the
// operator's current credential and endpoint.
func verifyOperatorClients(profile Profile, state inspected) ([]string, error) {
	evidence := make([]string, 0, len(profile.OperatorClients))
	for _, value := range profile.OperatorClients {
		operator := state.operators[value.OperatorID]
		path, err := clientconfig.OperatorPath(operator.Home, value.BrokerName)
		if err != nil {
			return nil, err
		}
		if !operatorClientCurrent(path, operator, value, state.storeSecrets[value.SecretSlot]) {
			return nil, fmt.Errorf("operator client %q does not match", value.OperatorID)
		}
		evidence = append(evidence, "operator client "+value.OperatorID+" for "+value.BrokerName+" matches")
	}
	return evidence, nil
}

func operatorClientCurrent(path string, operator api.OperatorBinding, spec OperatorClient, expectedSecret []byte) bool {
	if len(expectedSecret) == 0 {
		return false
	}
	owner, err := user.Lookup(operator.UnixUser)
	if err != nil {
		return false
	}
	uid, err := strconv.Atoi(owner.Uid)
	if err != nil {
		return false
	}
	value, err := clientconfig.ReadOperatorPath(path, uid)
	return err == nil && value.Endpoint == spec.Endpoint && value.Secret == string(expectedSecret)
}
