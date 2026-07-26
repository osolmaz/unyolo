package privilege

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"slices"

	deploymentruntime "github.com/osolmaz/brokerkit/deployment/runtime"
)

var releasePattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$`)

// Client owns one short-lived sudo setup worker process.
type Client struct {
	command *exec.Cmd
	input   io.WriteCloser
	output  io.ReadCloser
}

// Start downloads the root bootstrap from the exact release tag inside the
// sudo process. The downloaded script independently verifies the worker.
func Start(ctx context.Context, release string, stderr io.Writer) (*Client, error) {
	if !releasePattern.MatchString(release) {
		return nil, errors.New("setup worker requires an exact release version")
	}
	tag := "brokerkit/" + release
	url := "https://api.github.com/repos/osolmaz/brokerkit/contents/install/bootstrap-root.sh?ref=brokerkit%2F" + release
	script := `set -eu; tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT HUP INT TERM; curl -fL --proto '=https' --tlsv1.2 -H 'Accept: application/vnd.github.raw+json' "$1" -o "$tmp"; chmod 0500 "$tmp"; exec sh "$tmp" "$2"`
	command := exec.CommandContext(ctx, "sudo", "sh", "-c", script, "brokerkit-bootstrap", url, tag) // #nosec G204 -- fixed command with validated release-derived values.
	input, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := command.StdoutPipe()
	if err != nil {
		_ = input.Close()
		return nil, err
	}
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		_ = input.Close()
		_ = output.Close()
		return nil, err
	}
	return &Client{command: command, input: input, output: output}, nil
}

// Plan asks the worker to inspect protected state and return one plan.
func (client *Client) Plan(profile string) (Response, error) {
	if err := deploymentruntime.WriteFrame(client.input, Request{APIVersion: APIVersion, Profile: profile}); err != nil {
		return Response{}, err
	}
	var response Response
	if err := deploymentruntime.ReadFrame(client.output, &response); err != nil {
		return Response{}, err
	}
	if response.APIVersion != APIVersion || response.PlanDigest == "" || response.Plan.Digest != response.PlanDigest {
		return Response{}, errors.New("setup worker returned an invalid plan")
	}
	return response, nil
}

// Apply binds the exact plan and streams transient secret frames.
func (client *Client) Apply(planDigest string, secrets map[string][]byte) (Result, error) {
	names := make([]string, 0, len(secrets))
	for name := range secrets {
		names = append(names, name)
	}
	slices.Sort(names)
	decision := Decision{APIVersion: APIVersion, Action: "apply", PlanDigest: planDigest, SecretSlots: names}
	if err := deploymentruntime.WriteFrame(client.input, decision); err != nil {
		return Result{}, err
	}
	for _, name := range names {
		if err := deploymentruntime.WriteFrame(client.input, SecretFrame{APIVersion: APIVersion, Name: name, Value: secrets[name]}); err != nil {
			return Result{}, err
		}
	}
	if err := client.input.Close(); err != nil {
		return Result{}, err
	}
	var result Result
	if err := deploymentruntime.ReadFrame(client.output, &result); err != nil {
		return Result{}, err
	}
	if err := client.command.Wait(); err != nil {
		return Result{}, fmt.Errorf("setup worker failed: %w", err)
	}
	if result.APIVersion != APIVersion || result.Status != "succeeded" {
		return Result{}, errors.New("setup worker did not succeed")
	}
	return result, nil
}

// Cancel asks the worker to exit without mutation.
func (client *Client) Cancel() error {
	if err := deploymentruntime.WriteFrame(client.input, Decision{APIVersion: APIVersion, Action: "cancel"}); err != nil {
		return err
	}
	_ = client.input.Close()
	var result Result
	if err := deploymentruntime.ReadFrame(client.output, &result); err != nil {
		return err
	}
	return client.command.Wait()
}

// Close terminates an abandoned worker.
func (client *Client) Close() error {
	if client == nil || client.command == nil || client.command.Process == nil {
		return nil
	}
	_ = client.input.Close()
	_ = client.output.Close()
	if client.command.ProcessState == nil {
		_ = client.command.Process.Kill()
	}
	return nil
}

func clearSecretMap(values map[string][]byte) {
	for _, value := range values {
		clear(value)
	}
}
