package hubclient

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
)

var variableKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

const maxVariableValueBytes = 16 * 1024

// ValidVariableKey reports whether key is a safe environment-style variable
// name.
func ValidVariableKey(key string) bool { return variableKeyPattern.MatchString(key) }

// SpaceRuntime reads the observed runtime state of one exact Space.
//
// Spec: GET /api/spaces/{owner}/{name}/runtime.
func (c *Client) SpaceRuntime(ctx context.Context, space SpaceRef) (SpaceRuntime, error) {
	return readResource(ctx, c, space.Validate, space.apiPath("runtime"), func(wire spaceRuntimeWire) SpaceRuntime { return wire.toRuntime() })
}

// RestartSpace restarts one exact Space.
//
// Spec: POST /api/spaces/{owner}/{name}/restart[?factory=true].
func (c *Client) RestartSpace(ctx context.Context, space SpaceRef, factoryReboot bool) (SpaceRuntime, error) {
	if err := space.Validate(); err != nil {
		return SpaceRuntime{}, err
	}
	spec := callSpec{method: http.MethodPost, path: space.apiPath("restart")}
	if factoryReboot {
		spec.query = url.Values{"factory": []string{"true"}}
	}
	return c.runtimeCall(ctx, spec)
}

// PauseSpace pauses one exact Space.
//
// Spec: POST /api/spaces/{owner}/{name}/pause.
func (c *Client) PauseSpace(ctx context.Context, space SpaceRef) (SpaceRuntime, error) {
	if err := space.Validate(); err != nil {
		return SpaceRuntime{}, err
	}
	return c.runtimeCall(ctx, callSpec{method: http.MethodPost, path: space.apiPath("pause")})
}

type spaceHardwareBody struct {
	Flavor           string `json:"flavor"`
	SleepTimeSeconds *int   `json:"sleepTimeSeconds,omitempty"`
}

// RequestSpaceHardware requests exact hardware and optional sleep settings.
//
// Spec: POST /api/spaces/{owner}/{name}/hardware.
func (c *Client) RequestSpaceHardware(ctx context.Context, space SpaceRef, flavor string, sleepTimeSeconds *int) (SpaceRuntime, error) {
	if err := space.Validate(); err != nil {
		return SpaceRuntime{}, err
	}
	if !ValidHardwareFlavor(flavor) {
		return SpaceRuntime{}, errors.New("hubclient: space hardware flavor is not in the pinned set")
	}
	if sleepTimeSeconds != nil && *sleepTimeSeconds < -1 {
		return SpaceRuntime{}, errors.New("hubclient: sleep time must be -1 or a non-negative number of seconds")
	}
	spec := callSpec{
		method: http.MethodPost,
		path:   space.apiPath("hardware"),
		body:   spaceHardwareBody{Flavor: flavor, SleepTimeSeconds: sleepTimeSeconds},
	}
	return c.runtimeCall(ctx, spec)
}

type spaceSleepTimeBody struct {
	Seconds int `json:"seconds"`
}

func (c *Client) SetSpaceSleepTime(ctx context.Context, space SpaceRef, seconds int) (SpaceRuntime, error) {
	if err := space.Validate(); err != nil {
		return SpaceRuntime{}, err
	}
	if seconds < -1 {
		return SpaceRuntime{}, errors.New("hubclient: sleep time must be -1 or a non-negative number of seconds")
	}
	return c.runtimeCall(ctx, callSpec{method: http.MethodPost, path: space.apiPath("sleeptime"), body: spaceSleepTimeBody{Seconds: seconds}})
}

type spaceDevModeBody struct {
	Enabled bool `json:"enabled"`
}

func (c *Client) SetSpaceDevMode(ctx context.Context, space SpaceRef, enabled bool) (SpaceRuntime, error) {
	if err := space.Validate(); err != nil {
		return SpaceRuntime{}, err
	}
	return c.runtimeCall(ctx, callSpec{method: http.MethodPost, path: space.apiPath("dev-mode"), body: spaceDevModeBody{Enabled: enabled}})
}

func (c *Client) runtimeCall(ctx context.Context, spec callSpec) (SpaceRuntime, error) {
	var wire spaceRuntimeWire
	spec.out = &wire
	if err := c.call(ctx, spec); err != nil {
		return SpaceRuntime{}, err
	}
	return wire.toRuntime(), nil
}

// SpaceVariables lists the non-secret variables of one exact Space.
//
// Spec: GET /api/spaces/{owner}/{name}/variables.
func (c *Client) SpaceVariables(ctx context.Context, space SpaceRef) (map[string]SpaceVariable, error) {
	if err := space.Validate(); err != nil {
		return nil, err
	}
	variables := map[string]SpaceVariable{}
	err := c.call(ctx, callSpec{method: http.MethodGet, path: space.apiPath("variables"), out: &variables})
	if err != nil {
		return nil, err
	}
	return variables, nil
}

type setVariableBody struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
}

// SetSpaceVariable upserts one exact non-secret variable.
//
// Spec: POST /api/spaces/{owner}/{name}/variables.
func (c *Client) SetSpaceVariable(ctx context.Context, space SpaceRef, key, value, description string) error {
	if err := space.Validate(); err != nil {
		return err
	}
	if err := validateVariableKey(key); err != nil {
		return err
	}
	if len(value) > maxVariableValueBytes {
		return errors.New("hubclient: variable value is too large")
	}
	spec := callSpec{
		method: http.MethodPost,
		path:   space.apiPath("variables"),
		body:   setVariableBody{Key: key, Value: value, Description: description},
	}
	return c.call(ctx, spec)
}

type deleteVariableBody struct {
	Key string `json:"key"`
}

// DeleteSpaceVariable deletes one exact variable.
//
// Spec: DELETE /api/spaces/{owner}/{name}/variables.
func (c *Client) DeleteSpaceVariable(ctx context.Context, space SpaceRef, key string) error {
	if err := space.Validate(); err != nil {
		return err
	}
	if err := validateVariableKey(key); err != nil {
		return err
	}
	spec := callSpec{
		method: http.MethodDelete,
		path:   space.apiPath("variables"),
		body:   deleteVariableBody{Key: key},
	}
	return c.call(ctx, spec)
}

func validateVariableKey(key string) error {
	if !ValidVariableKey(key) {
		return errors.New("hubclient: variable key must be an environment-style identifier")
	}
	return nil
}
