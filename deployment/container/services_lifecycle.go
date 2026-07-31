package container

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ServicesComposeFilename is the fixed compose file emitted by the services
// compiler.
const ServicesComposeFilename = "unyolo-services.compose.yml"

// ServicesReceiptFilename is the receipt persisted after apply.
const ServicesReceiptFilename = "unyolo-services.receipt.json"

// ServicesReceipt records the exact broker resources unYOLO created so
// removal can distinguish installation-owned volumes from operator-created
// paths.
type ServicesReceipt struct {
	APIVersion       string   `json:"api_version"`
	InstallationName string   `json:"installation_name"`
	ProjectName      string   `json:"project_name"`
	Network          string   `json:"network"`
	Services         []string `json:"services"`
	Volumes          []string `json:"volumes"`
	Secrets          []string `json:"secrets"`
}

const receiptAPIVersion = "unyolo.io/services-receipt/v1"

// PlanServices writes the deterministic compose file into the installation
// directory and returns a rollback that restores the previous file.
type ServicesPlanInputs struct {
	Directory string
	Project   *ServicesProject
	FileMode  os.FileMode
}

// ServicesPlanResult holds the exact path we wrote and the previous state so
// rollback can restore it.
type ServicesPlanResult struct {
	ComposePath      string
	PreviousExisted  bool
	PreviousContent  []byte
	PreviousFileMode os.FileMode
}

// Plan writes the services compose file atomically and returns a rollback.
func PlanServices(inputs ServicesPlanInputs) (ServicesPlanResult, func() error, error) {
	if inputs.Project == nil {
		return ServicesPlanResult{}, nil, errors.New("services project is required")
	}
	if !filepath.IsAbs(inputs.Directory) || filepath.Clean(inputs.Directory) != inputs.Directory {
		return ServicesPlanResult{}, nil, errors.New("services directory must be absolute and clean")
	}
	mode := inputs.FileMode
	if mode == 0 {
		mode = 0o600
	}
	composePath := filepath.Join(inputs.Directory, ServicesComposeFilename)
	rendered, err := inputs.Project.Render()
	if err != nil {
		return ServicesPlanResult{}, nil, err
	}
	previous, existed, err := readExisting(composePath)
	if err != nil {
		return ServicesPlanResult{}, nil, err
	}
	if err := writeAtomic(composePath, rendered, mode); err != nil {
		return ServicesPlanResult{}, nil, err
	}
	rollback := func() error {
		return restoreExisting(composePath, previous, existed, mode)
	}
	return ServicesPlanResult{
		ComposePath: composePath, PreviousExisted: existed, PreviousContent: previous, PreviousFileMode: mode,
	}, rollback, nil
}

// PullImages runs `docker compose pull` for the credential services. The
// operation is idempotent and does not start any container.
func PullImages(ctx context.Context, runner Runner, options ProjectOptions, composePath string) error {
	return runComposeAction(ctx, runner, options, composePath, "pull")
}

// UpServices runs `docker compose up -d` to bring the credential services
// online.
func UpServices(ctx context.Context, runner Runner, options ProjectOptions, composePath string) error {
	return runComposeAction(ctx, runner, options, composePath, "up", "-d", "--remove-orphans")
}

// RestartService restarts one broker service.
func RestartService(ctx context.Context, runner Runner, options ProjectOptions, composePath, service string) error {
	if !composeServiceNamePattern.MatchString(service) {
		return errors.New("service name is invalid")
	}
	return runComposeAction(ctx, runner, options, composePath, "restart", service)
}

// StopServices stops every credential service but retains volumes.
func StopServices(ctx context.Context, runner Runner, options ProjectOptions, composePath string) error {
	return runComposeAction(ctx, runner, options, composePath, "stop")
}

// DownServices runs `docker compose down`, retaining named volumes and
// declared networks. Volumes are only removed by DestroyVolumes with an
// explicit confirmation.
func DownServices(ctx context.Context, runner Runner, options ProjectOptions, composePath string) error {
	return runComposeAction(ctx, runner, options, composePath, "down", "--remove-orphans")
}

// DestroyVolumes removes the exact volumes named in the receipt. It is a
// separately confirmed destructive action and must never be invoked as part
// of a normal removal.
func DestroyVolumes(ctx context.Context, runner Runner, receipt ServicesReceipt, confirmed bool) error {
	if !confirmed {
		return errors.New("volume destruction requires explicit operator confirmation")
	}
	if runner == nil {
		runner = CLIRunner{}
	}
	if receipt.APIVersion != receiptAPIVersion {
		return errors.New("services receipt is invalid")
	}
	for _, volume := range receipt.Volumes {
		if !isValidVolumeName(volume) {
			return fmt.Errorf("receipt names an invalid volume %q", volume)
		}
		_, stderr, err := runner.Run(ctx, os.TempDir(), "volume", "rm", volume)
		if err != nil && !strings.Contains(strings.ToLower(string(stderr)), "no such volume") {
			return fmt.Errorf("remove volume %s: %w: %s", volume, err, strings.TrimSpace(string(stderr)))
		}
	}
	return nil
}

// WriteReceipt persists the exact broker resources the plan created so we can
// later distinguish installation-owned from operator-created resources.
func WriteReceipt(directory string, project *ServicesProject, installationName string) (string, error) {
	if project == nil {
		return "", errors.New("services project is required")
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return "", errors.New("services directory must be absolute and clean")
	}
	if !installationBrokerPattern.MatchString(installationName) {
		return "", errors.New("installation name is invalid")
	}
	receipt := ServicesReceipt{
		APIVersion: receiptAPIVersion, InstallationName: installationName,
		ProjectName: project.ProjectName, Network: project.NetworkName,
	}
	for _, broker := range project.Brokers {
		receipt.Services = append(receipt.Services, broker.Name)
		for _, secret := range broker.Secrets {
			receipt.Secrets = append(receipt.Secrets, secret.Name)
		}
	}
	for _, volume := range project.SharedVolumes {
		receipt.Volumes = append(receipt.Volumes, volume.Name)
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(directory, ServicesReceiptFilename)
	if err := writeAtomic(path, append(data, '\n'), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// LoadReceipt reads and validates a persisted services receipt.
func LoadReceipt(path string) (ServicesReceipt, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ServicesReceipt{}, errors.New("receipt path must be absolute and clean")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- validated caller path.
	if err != nil {
		return ServicesReceipt{}, err
	}
	var receipt ServicesReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		return ServicesReceipt{}, fmt.Errorf("decode services receipt: %w", err)
	}
	if receipt.APIVersion != receiptAPIVersion {
		return ServicesReceipt{}, errors.New("services receipt API version is invalid")
	}
	return receipt, nil
}

func runComposeAction(ctx context.Context, runner Runner, options ProjectOptions, composePath string, arguments ...string) error {
	if runner == nil {
		runner = CLIRunner{}
	}
	if err := options.Validate(); err != nil {
		return err
	}
	if !filepath.IsAbs(composePath) || filepath.Clean(composePath) != composePath {
		return errors.New("compose path must be absolute and clean")
	}
	base := []string{"compose"}
	if options.ProjectName != "" {
		base = append(base, "-p", options.ProjectName)
	}
	base = append(base, "-f", composePath)
	base = append(base, arguments...)
	_, stderr, err := runner.Run(ctx, options.Directory, base...)
	if err != nil {
		return fmt.Errorf("docker compose %s: %w: %s", strings.Join(arguments, " "), err, strings.TrimSpace(string(stderr)))
	}
	return nil
}
