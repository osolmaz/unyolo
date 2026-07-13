package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/brokers/github/internal/githubauth"
	"github.com/osolmaz/brokerkit/credentialstore"
)

const maxUserSetupFileBytes = 128 * 1024

type githubUserSetupOptions struct {
	action       string
	stateDir     string
	credential   string
	userID       int64
	clientID     string
	clientSecret string
	apiURL       string
	webURL       string
}

func runSetupGitHubUser(ctx context.Context, stdout, stderr io.Writer, args []string) error {
	if len(args) == 0 || (args[0] != "enroll" && args[0] != "rotate" && args[0] != "revoke") {
		return errors.New(setupUsage)
	}
	opts, err := parseGitHubUserSetup(stderr, args[0], args[1:])
	if err != nil {
		return err
	}
	return executeGitHubUserSetup(ctx, stdout, opts)
}

func parseGitHubUserSetup(stderr io.Writer, action string, args []string) (githubUserSetupOptions, error) {
	fs := flag.NewFlagSet("gh-broker setup github-user "+action, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var opts githubUserSetupOptions
	opts.action = action
	fs.StringVar(&opts.stateDir, "state-dir", "", "gh-broker state directory")
	fs.StringVar(&opts.credential, "credential-file", "", "protected JSON file containing expiring access and refresh credentials")
	fs.Int64Var(&opts.userID, "user-id", 0, "immutable GitHub user id to revoke")
	fs.StringVar(&opts.clientID, "github-app-client-id-file", "", "protected file containing the GitHub App client id")
	fs.StringVar(&opts.clientSecret, "github-app-client-secret-file", "", "protected file containing the GitHub App client secret")
	fs.StringVar(&opts.apiURL, "github-api-url", "https://api.github.com/", "GitHub API base URL")
	fs.StringVar(&opts.webURL, "github-web-url", "https://github.com/", "GitHub web base URL")
	if err := fs.Parse(args); err != nil {
		return githubUserSetupOptions{}, err
	}
	if err := validateGitHubUserSetup(fs.NArg(), opts); err != nil {
		return githubUserSetupOptions{}, err
	}
	return opts, nil
}

func validateGitHubUserSetup(extraArgs int, opts githubUserSetupOptions) error {
	if extraArgs != 0 || opts.stateDir == "" || opts.clientID == "" || opts.clientSecret == "" {
		return errors.New("github-user setup requires state and GitHub App client credential files")
	}
	return validateGitHubUserAction(opts)
}

func validateGitHubUserAction(opts githubUserSetupOptions) error {
	if opts.action == "revoke" && (opts.userID <= 0 || opts.credential != "") {
		return errors.New("github-user revoke requires --user-id and does not accept --credential-file")
	}
	if opts.action != "revoke" && (opts.credential == "" || opts.userID != 0) {
		return errors.New("github-user enroll and rotate require --credential-file and do not accept --user-id")
	}
	return nil
}

func executeGitHubUserSetup(ctx context.Context, stdout io.Writer, opts githubUserSetupOptions) error {
	manager, err := newGitHubUserSetupManager(opts)
	if err != nil {
		return err
	}
	if opts.action == "revoke" {
		if err := manager.RevokeUser(ctx, opts.userID); err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "revoked GitHub user credential for user %d\n", opts.userID)
		return err
	}
	return storeGitHubUserSetup(ctx, stdout, opts, manager)
}

func newGitHubUserSetupManager(opts githubUserSetupOptions) (*githubauth.Manager, error) {
	clientID, err := readProtectedSetupFile(opts.clientID)
	if err != nil {
		return nil, fmt.Errorf("read GitHub App client id: %w", err)
	}
	clientSecret, err := readProtectedSetupFile(opts.clientSecret)
	if err != nil {
		return nil, fmt.Errorf("read GitHub App client secret: %w", err)
	}
	defer clearBytes(clientID)
	defer clearBytes(clientSecret)
	apiURL, apiErr := url.Parse(opts.apiURL)
	webURL, webErr := url.Parse(opts.webURL)
	if apiErr != nil || webErr != nil {
		return nil, errors.New("GitHub base URL is invalid")
	}
	store, err := credentialstore.Open(opts.stateDir)
	if err != nil {
		return nil, err
	}
	manager, err := githubauth.New(githubauth.Config{AppClientID: strings.TrimSpace(string(clientID)), AppClientSecret: clientSecret,
		APIBaseURL: apiURL, WebBaseURL: webURL, Store: store, HTTPClient: &http.Client{Timeout: 30 * time.Second, CheckRedirect: stopUserSetupRedirect}})
	if err != nil {
		return nil, err
	}
	return manager, nil
}

func storeGitHubUserSetup(ctx context.Context, stdout io.Writer, opts githubUserSetupOptions, manager *githubauth.Manager) error {
	data, err := readProtectedSetupFile(opts.credential)
	if err != nil {
		return fmt.Errorf("read GitHub user credential: %w", err)
	}
	defer clearBytes(data)
	enrollment, err := githubauth.DecodeUserEnrollment(data)
	if err != nil {
		return err
	}
	defer clearBytes(enrollment.AccessToken)
	defer clearBytes(enrollment.RefreshToken)
	if opts.action == "enroll" {
		err = manager.EnrollUser(ctx, enrollment)
	} else {
		err = manager.RotateUser(ctx, enrollment)
	}
	if err != nil {
		return err
	}
	pastTense := "enrolled"
	if opts.action == "rotate" {
		pastTense = "rotated"
	}
	_, err = fmt.Fprintf(stdout, "%s GitHub user credential for user %d\n", pastTense, enrollment.UserID)
	return err
}

func readProtectedSetupFile(path string) ([]byte, error) {
	info, err := os.Lstat(path) // #nosec G703 -- local operator-supplied protected path.
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("credential file must be a regular protected file")
	}
	file, err := os.Open(path) // #nosec G304,G703 -- local operator-supplied protected path.
	if err != nil {
		return nil, errors.New("open credential file")
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxUserSetupFileBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxUserSetupFileBytes {
		clearBytes(data)
		return nil, errors.New("credential file is empty, unreadable, or too large")
	}
	return data, nil
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func stopUserSetupRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
