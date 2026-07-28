// Package xetuploader uploads broker-owned files through the maintained hf_xet
// implementation without exposing Hub or Xet credentials to Agent clients.
package xetuploader

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/osolmaz/unyolo/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/xethash"
	"github.com/osolmaz/unyolo/internal/strictjson"
)

const (
	maxHelperOutput = 4096
	defaultTimeout  = 30 * time.Minute
)

// Result is the safe content identity returned by hf_xet.
type Result struct {
	Hash string `json:"hash"`
	Size int64  `json:"size"`
}

// Uploader invokes one fixed isolated helper against one pinned Hub origin.
type Uploader struct {
	python   string
	endpoint string
	token    string
	timeout  time.Duration
}

// New constructs an uploader. python must resolve to a trusted interpreter
// with the release-pinned hf_xet package installed.
func New(python, endpoint, token string, timeout time.Duration) (*Uploader, error) {
	if python == "" {
		python = "python3"
	}
	resolved, err := exec.LookPath(python)
	parsed, parseErr := url.Parse(endpoint)
	if err != nil || parseErr != nil || !validEndpoint(parsed) || strings.TrimSpace(token) == "" {
		return nil, errors.New("xet uploader configuration is invalid")
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Uploader{python: resolved, endpoint: strings.TrimRight(parsed.String(), "/"), token: token, timeout: timeout}, nil
}

func validEndpoint(endpoint *url.URL) bool {
	return endpoint != nil && (endpoint.Scheme == "https" || endpoint.Scheme == "http") && endpoint.Host != "" &&
		endpoint.User == nil && endpoint.Path == "" && endpoint.RawQuery == "" && endpoint.Fragment == ""
}

// Upload sends one verified private stream file to Xet and returns its Xet
// file hash. The Hub token travels only over the child process stdin pipe.
func (u *Uploader) Upload(ctx context.Context, ref hubclient.BucketRef, file *os.File, size int64) (Result, error) {
	if !validUploadInput(u, ref, file, size) {
		return Result{}, errors.New("xet upload input is invalid")
	}
	ctx, cancel := context.WithTimeout(ctx, u.timeout)
	defer cancel()
	stdout, err := u.runHelper(ctx, helperInput{Path: file.Name(), Size: size, Token: u.token,
		RefreshURL: u.endpoint + "/api/buckets/" + url.PathEscape(ref.Namespace) + "/" + url.PathEscape(ref.Name) + "/xet-write-token"})
	if err != nil {
		return Result{}, err
	}
	var result Result
	if strictjson.Decode(stdout, &result, true) != nil || result.Size != size || !validHash(result.Hash) {
		return Result{}, errors.New("xet upload returned invalid metadata")
	}
	return result, nil
}

func validUploadInput(u *Uploader, ref hubclient.BucketRef, file *os.File, size int64) bool {
	return u != nil && ref.Validate() == nil && file != nil && size > 0 && filepath.IsAbs(file.Name())
}

func (u *Uploader) runHelper(ctx context.Context, input helperInput) ([]byte, error) {
	payload, _ := json.Marshal(input)
	command := exec.CommandContext(ctx, u.python, "-I", "-c", helperScript) // #nosec G204 -- interpreter is resolved at trusted startup; script and arguments are fixed.
	command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "PYTHONNOUSERSITE=1"}
	command.Stdin = bytes.NewReader(payload)
	var stdout bytes.Buffer
	command.Stdout = &limitedWriter{destination: &stdout, remaining: maxHelperOutput}
	command.Stderr = &limitedWriter{remaining: maxHelperOutput}
	if err := command.Run(); err != nil {
		return nil, errors.New("xet upload failed")
	}
	return stdout.Bytes(), nil
}

type helperInput struct {
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	Token      string `json:"token"`
	RefreshURL string `json:"refresh_url"`
}

type limitedWriter struct {
	destination *bytes.Buffer
	remaining   int
}

func (w *limitedWriter) Write(value []byte) (int, error) {
	if len(value) > w.remaining {
		return 0, errors.New("helper output exceeds limit")
	}
	w.remaining -= len(value)
	if w.destination != nil {
		_, _ = w.destination.Write(value)
	}
	return len(value), nil
}

func validHash(value string) bool { return xethash.Valid(value) }

const helperScript = `
import json, sys
from hf_xet import SKIP_SHA256, XetSession
value = json.load(sys.stdin)
headers = {"authorization": "Bearer " + value["token"]}
session = XetSession()
with session.new_upload_commit(
    token_refresh_url=value["refresh_url"],
    token_refresh_headers=headers,
    custom_headers={},
) as commit:
    handle = commit.start_upload_file(value["path"], sha256=SKIP_SHA256)
result = handle.result().xet_info
json.dump({"hash": result.hash, "size": result.file_size}, sys.stdout)
`
