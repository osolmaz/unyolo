package xetuploader

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
)

func TestUploaderUsesFixedHelperAndStdinCredential(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	capture := filepath.Join(directory, "input.json")
	helper := filepath.Join(directory, "helper")
	script := "#!/bin/sh\ncat > " + capture + "\nprintf '{\"hash\":\"" + strings.Repeat("a", 64) + "\",\"size\":4}'\n"
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(directory, "stream")
	if err := os.WriteFile(filePath, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	uploader, err := New(helper, "https://huggingface.co", "hf_secret", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	result, err := uploader.Upload(t.Context(), hubclient.BucketRef{Namespace: "acme", Name: "artifacts"}, file, 4)
	if err != nil || result.Size != 4 {
		t.Fatalf("Upload() = %+v, %v", result, err)
	}
	input, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	text := string(input)
	if !strings.Contains(text, `"token":"hf_secret"`) || !strings.Contains(text, `"refresh_url":"https://huggingface.co/api/buckets/acme/artifacts/xet-write-token"`) {
		t.Fatalf("helper input = %s", input)
	}
}

func TestUploaderRejectsUnsafeConfigurationAndOutput(t *testing.T) {
	t.Parallel()
	if _, err := New("missing-helper", "https://huggingface.co", "token", time.Minute); err == nil {
		t.Fatal("New() accepted missing helper")
	}
	if _, err := New("sh", "https://user:pass@huggingface.co/path", "token", time.Minute); err == nil {
		t.Fatal("New() accepted unsafe endpoint")
	}
}
