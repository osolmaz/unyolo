package privilege

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
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
	"syscall"

	deploymentruntime "github.com/osolmaz/unyolo/deployment/runtime"
)

const githubAttestationsURL = "https://api.github.com/repos/osolmaz/unyolo/attestations"

var (
	releasePattern  = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$`)
	commitPattern   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	checksumPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Client owns one short-lived sudo setup worker process.
type Client struct {
	command   *exec.Cmd
	input     io.WriteCloser
	output    io.ReadCloser
	temporary string
}

// Start verifies the release-published root bootstrap as the operator, then
// asks root to copy, rehash, and execute only the root-owned copy.
func Start(ctx context.Context, release, sourceCommit, githubCLI string, stderr io.Writer) (*Client, error) {
	if !releasePattern.MatchString(release) || !commitPattern.MatchString(sourceCommit) {
		return nil, errors.New("setup worker requires an exact release version and source commit")
	}
	verifierDigest, err := trustedGitHubCLI(githubCLI)
	if err != nil {
		return nil, err
	}
	temporary, bootstrap, expected, err := prepareRootBootstrap(ctx, release, sourceCommit, githubCLI, stderr)
	if err != nil {
		return nil, err
	}
	tag := "unyolo/" + release
	build := strings.TrimPrefix(release, "v")
	command := rootWorkerCommand(ctx, bootstrap, expected, githubCLI, verifierDigest, build, tag, sourceCommit)
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

func trustedGitHubCLI(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("GitHub attestation verifier path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil || !validGitHubCLIMetadata(info) {
		return "", errors.New("GitHub attestation verifier is missing or unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return "", errors.New("GitHub attestation verifier is not owned by the invoking operator")
	}
	file, err := os.Open(path) // #nosec G304 -- validated operator-owned verifier path.
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		return "", errors.Join(copyErr, closeErr)
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func validGitHubCLIMetadata(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o022 == 0 &&
		info.Mode().Perm()&0o111 != 0 && info.Size() >= 1 && info.Size() <= 256*1024*1024
}

func rootWorkerCommand(ctx context.Context, bootstrap, expected, githubCLI, verifierDigest, build, tag, sourceCommit string) *exec.Cmd {
	script := `set -eu; bootstrap=$1; bootstrap_digest=$2; verifier=$3; verifier_digest=$4; build=$5; tag=$6; source_commit=$7; destination="/opt/unyolo/bootstrap/$build"; install -d -o root -g root -m 0755 "$destination"; install -o root -g root -m 0500 "$bootstrap" "$destination/bootstrap-root.sh.new"; install -o root -g root -m 0500 "$verifier" "$destination/gh-attestation-verifier.new"; bootstrap_actual=$(sha256sum "$destination/bootstrap-root.sh.new" 2>/dev/null | awk '{print $1}') || bootstrap_actual=$(shasum -a 256 "$destination/bootstrap-root.sh.new" | awk '{print $1}'); verifier_actual=$(sha256sum "$destination/gh-attestation-verifier.new" 2>/dev/null | awk '{print $1}') || verifier_actual=$(shasum -a 256 "$destination/gh-attestation-verifier.new" | awk '{print $1}'); [ "$bootstrap_actual" = "$bootstrap_digest" ]; [ "$verifier_actual" = "$verifier_digest" ]; mv -f "$destination/bootstrap-root.sh.new" "$destination/bootstrap-root.sh"; mv -f "$destination/gh-attestation-verifier.new" "$destination/gh-attestation-verifier"; UNYOLO_GH_VERIFIER="$destination/gh-attestation-verifier" exec "$destination/bootstrap-root.sh" "$tag" "$source_commit"`
	return exec.CommandContext(ctx, "sudo", "sh", "-c", script, "unyolo-root-stage", bootstrap, expected, githubCLI, verifierDigest, build, tag, sourceCommit) // #nosec G204 -- fixed staging command with verified release-derived values.
}

func prepareRootBootstrap(ctx context.Context, release, sourceCommit, githubCLI string, stderr io.Writer) (string, string, string, error) {
	temporary, err := os.MkdirTemp("", "unyolo-root-bootstrap.*")
	if err != nil {
		return "", "", "", err
	}
	fail := func(err error) (string, string, string, error) {
		_ = os.RemoveAll(temporary)
		return "", "", "", err
	}
	base := "https://github.com/osolmaz/unyolo/releases/download/unyolo/" + release
	bootstrap := filepath.Join(temporary, "unyolo-bootstrap-root.sh")
	if err := download(ctx, base+"/unyolo-bootstrap-root.sh", bootstrap, 256*1024); err != nil {
		return fail(err)
	}
	checksums := filepath.Join(temporary, "checksums.txt")
	if err := download(ctx, base+"/checksums.txt", checksums, 4*1024*1024); err != nil {
		return fail(err)
	}
	expected, err := checksumFor(checksums, "unyolo-bootstrap-root.sh")
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
	bundles := filepath.Join(temporary, "attestations.jsonl")
	if err := downloadAttestationBundles(ctx, githubAttestationsURL, expected, bundles); err != nil {
		return fail(fmt.Errorf("download root bootstrap attestations: %w", err))
	}
	workflow := "osolmaz/unyolo/.github/workflows/release.yml"
	command := exec.CommandContext(ctx, githubCLI, "attestation", "verify", bootstrap, "--bundle", bundles,
		"--repo", "osolmaz/unyolo", "--signer-workflow", workflow,
		"--source-ref", "refs/tags/unyolo/"+release, "--source-digest", sourceCommit,
		"--deny-self-hosted-runners") // #nosec G204 -- fixed verifier and validated release identity.
	command.Stdout, command.Stderr = io.Discard, stderr
	if err := command.Run(); err != nil {
		return fail(fmt.Errorf("verify root bootstrap provenance: %w", err))
	}
	return temporary, bootstrap, expected, nil
}

type githubAttestationResponse struct {
	Attestations []struct {
		Bundle json.RawMessage `json:"bundle"`
	} `json:"attestations"`
}

func downloadAttestationBundles(ctx context.Context, baseURL, digest, destination string) error {
	if !checksumPattern.MatchString(digest) {
		return errors.New("attestation subject digest is invalid")
	}
	responsePath := destination + ".response"
	if err := download(ctx, strings.TrimSuffix(baseURL, "/")+"/sha256:"+digest+"?per_page=30", responsePath, 8*1024*1024); err != nil {
		return err
	}
	data, err := os.ReadFile(responsePath) // #nosec G304 -- private bounded download path.
	if err != nil {
		return err
	}
	bundles, err := parseAttestationBundles(data)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400) // #nosec G304 -- private temporary destination.
	if err != nil {
		return err
	}
	_, writeErr := file.Write(bundles)
	return errors.Join(writeErr, file.Close())
}

func parseAttestationBundles(data []byte) ([]byte, error) {
	var response githubAttestationResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("decode GitHub attestations: %w", err)
	}
	if len(response.Attestations) == 0 || len(response.Attestations) > 30 {
		return nil, errors.New("GitHub returned an invalid attestation count")
	}
	var bundles bytes.Buffer
	for _, attestation := range response.Attestations {
		if len(attestation.Bundle) == 0 || !json.Valid(attestation.Bundle) {
			return nil, errors.New("GitHub returned an invalid attestation bundle")
		}
		_, _ = bundles.Write(attestation.Bundle)
		_ = bundles.WriteByte('\n')
	}
	return bundles.Bytes(), nil
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
	return client.plan(Request{APIVersion: APIVersion, InputKind: "profile", Profile: profile})
}

// PlanInstallation asks root to recompile and compare a generated installation.
func (client *Client) PlanInstallation(installation, profile string) (Response, error) {
	return client.plan(Request{APIVersion: APIVersion, InputKind: "installation", Installation: installation, Profile: profile})
}

func (client *Client) plan(request Request) (Response, error) {
	if err := deploymentruntime.WriteFrame(client.input, request); err != nil {
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
