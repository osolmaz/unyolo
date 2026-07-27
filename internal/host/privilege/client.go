package privilege

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	deploymentruntime "github.com/osolmaz/brokerkit/deployment/runtime"
)

const maxGitHubTokenBytes = 4096

var (
	releasePattern  = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$`)
	checksumPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Client owns one short-lived sudo setup worker process.
type Client struct {
	command   *exec.Cmd
	input     io.WriteCloser
	output    io.ReadCloser
	temporary string
}

type boundedTokenBuffer struct {
	data     bytes.Buffer
	maximum  int
	exceeded bool
}

func (buffer *boundedTokenBuffer) Write(value []byte) (int, error) {
	remaining := buffer.maximum - buffer.data.Len()
	if remaining > 0 {
		_, _ = buffer.data.Write(value[:min(remaining, len(value))])
	}
	if len(value) > remaining {
		buffer.exceeded = true
	}
	return len(value), nil
}

// Start verifies the release-published root bootstrap as the operator, then
// asks root to copy, rehash, and execute only the root-owned copy.
func Start(ctx context.Context, release string, stderr io.Writer) (*Client, error) {
	if !releasePattern.MatchString(release) {
		return nil, errors.New("setup worker requires an exact release version")
	}
	temporary, bootstrap, expected, err := prepareRootBootstrap(ctx, release, stderr)
	if err != nil {
		return nil, err
	}
	token, err := githubToken(ctx)
	if err != nil {
		_ = os.RemoveAll(temporary)
		return nil, err
	}
	tag := "brokerkit/" + release
	build := strings.TrimPrefix(release, "v")
	command := rootWorkerCommand(ctx, bootstrap, expected, build, tag, token)
	clear(token)
	input, err := command.StdinPipe()
	if err != nil {
		command.Env = nil
		_ = os.RemoveAll(temporary)
		return nil, err
	}
	output, err := command.StdoutPipe()
	if err != nil {
		command.Env = nil
		_ = input.Close()
		_ = os.RemoveAll(temporary)
		return nil, err
	}
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		command.Env = nil
		_ = input.Close()
		_ = output.Close()
		_ = os.RemoveAll(temporary)
		return nil, err
	}
	command.Env = nil
	return &Client{command: command, input: input, output: output, temporary: temporary}, nil
}

func githubToken(ctx context.Context) ([]byte, error) {
	if value := strings.TrimSpace(os.Getenv("GH_TOKEN")); value != "" {
		if len(value) > maxGitHubTokenBytes {
			return nil, errors.New("GitHub authentication token exceeds size limit")
		}
		return []byte(value), nil
	}
	command := exec.CommandContext(ctx, "gh", "auth", "token")
	output := boundedTokenBuffer{maximum: maxGitHubTokenBytes}
	command.Stdout = &output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil || output.exceeded {
		clear(output.data.Bytes())
		return nil, errors.New("resolve GitHub authentication for root setup")
	}
	data := bytes.TrimSpace(output.data.Bytes())
	if len(data) == 0 {
		return nil, errors.New("GitHub authentication is required for root setup")
	}
	return data, nil
}

func rootWorkerCommand(ctx context.Context, bootstrap, expected, build, tag string, token []byte) *exec.Cmd {
	script := `set -eu; src=$1; expected=$2; build=$3; tag=$4; destination="/opt/brokerkit/bootstrap/$build"; install -d -o root -g root -m 0755 "$destination"; install -o root -g root -m 0500 "$src" "$destination/bootstrap-root.sh.new"; actual=$(sha256sum "$destination/bootstrap-root.sh.new" 2>/dev/null | awk '{print $1}') || actual=$(shasum -a 256 "$destination/bootstrap-root.sh.new" | awk '{print $1}'); [ "$actual" = "$expected" ]; mv -f "$destination/bootstrap-root.sh.new" "$destination/bootstrap-root.sh"; exec "$destination/bootstrap-root.sh" "$tag"`
	command := exec.CommandContext(ctx, "sudo", "--preserve-env=GH_TOKEN", "sh", "-c", script, "brokerkit-root-stage", bootstrap, expected, build, tag) // #nosec G204 -- fixed staging command with verified release-derived values.
	environment := make([]string, 0, len(os.Environ())+1)
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "GH_TOKEN=") {
			environment = append(environment, value)
		}
	}
	command.Env = append(environment, "GH_TOKEN="+string(token))
	return command
}

func prepareRootBootstrap(ctx context.Context, release string, stderr io.Writer) (string, string, string, error) {
	temporary, err := os.MkdirTemp("", "brokerkit-root-bootstrap.*")
	if err != nil {
		return "", "", "", err
	}
	fail := func(err error) (string, string, string, error) {
		_ = os.RemoveAll(temporary)
		return "", "", "", err
	}
	base := "https://github.com/osolmaz/brokerkit/releases/download/brokerkit/" + release
	bootstrap := filepath.Join(temporary, "brokerkit-bootstrap-root.sh")
	if err := download(ctx, base+"/brokerkit-bootstrap-root.sh", bootstrap, 256*1024); err != nil {
		return fail(err)
	}
	checksums := filepath.Join(temporary, "checksums.txt")
	if err := download(ctx, base+"/checksums.txt", checksums, 4*1024*1024); err != nil {
		return fail(err)
	}
	expected, err := checksumFor(checksums, "brokerkit-bootstrap-root.sh")
	if err != nil {
		return fail(err)
	}
	data, err := os.ReadFile(bootstrap) // #nosec G304 -- private temporary file created above.
	if err != nil {
		return fail(err)
	}
	actual := fmt.Sprintf("%x", sha256.Sum256(data))
	if actual != expected {
		return fail(errors.New("root bootstrap checksum mismatch"))
	}
	workflow := "osolmaz/brokerkit/.github/workflows/release.yml"
	command := exec.CommandContext(ctx, "gh", "attestation", "verify", bootstrap,
		"--repo", "osolmaz/brokerkit", "--signer-workflow", workflow,
		"--source-ref", "refs/tags/brokerkit/"+release, "--deny-self-hosted-runners") // #nosec G204 -- fixed verifier and validated release.
	command.Stdout, command.Stderr = io.Discard, stderr
	if err := command.Run(); err != nil {
		return fail(fmt.Errorf("verify root bootstrap provenance: %w", err))
	}
	return temporary, bootstrap, expected, nil
}

func download(ctx context.Context, source, destination string, maximum int64) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close() //nolint:errcheck // response body close does not affect the completed bounded download.
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("release download returned HTTP %d", response.StatusCode)
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400) // #nosec G304 -- destination is inside the private temporary directory.
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(file, io.LimitReader(response.Body, maximum+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		return errors.Join(copyErr, closeErr)
	}
	if written > maximum {
		return errors.New("release download exceeds size limit")
	}
	return nil
}

func checksumFor(path, name string) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- private temporary checksum file.
	if err != nil {
		return "", err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == name && checksumPattern.MatchString(fields[0]) {
			return fields[0], nil
		}
	}
	return "", errors.New("release checksum is missing")
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
		client.cleanup()
		return Result{}, fmt.Errorf("setup worker failed: %w", err)
	}
	client.cleanup()
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
	err := client.command.Wait()
	client.cleanup()
	return err
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
	client.cleanup()
	return nil
}

func (client *Client) cleanup() {
	if client == nil || client.temporary == "" {
		return
	}
	_ = os.RemoveAll(client.temporary)
	client.temporary = ""
}
