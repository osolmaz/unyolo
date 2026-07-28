package httpapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/brokers/huggingface/internal/config"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/gitproxy"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/policy"
)

func TestRefChangeForClassUsesPolicyVocabulary(t *testing.T) {
	zero := strings.Repeat("0", 40)
	oldSHA := strings.Repeat("a", 40)
	newSHA := strings.Repeat("b", 40)
	tests := []struct {
		name  string
		class gitproxy.ClassifiedCommand
		want  string
	}{
		{name: "create", class: gitproxy.ClassifiedCommand{Kind: gitproxy.RefUpdateAppend, Command: gitproxy.Command{Old: zero, New: newSHA}}, want: "create"},
		{name: "fast forward", class: gitproxy.ClassifiedCommand{Kind: gitproxy.RefUpdateAppend, Command: gitproxy.Command{Old: oldSHA, New: newSHA}}, want: "fast_forward"},
		{name: "rewrite", class: gitproxy.ClassifiedCommand{Kind: gitproxy.RefUpdateHistoryRewrite, Command: gitproxy.Command{Old: oldSHA, New: newSHA}}, want: "non_fast_forward"},
		{name: "delete", class: gitproxy.ClassifiedCommand{Kind: gitproxy.RefUpdateRefDelete, Command: gitproxy.Command{Old: oldSHA, New: zero}}, want: "delete"},
		{name: "tag", class: gitproxy.ClassifiedCommand{Kind: gitproxy.RefUpdateTagUpdate, Command: gitproxy.Command{Old: oldSHA, New: newSHA}}, want: "tag_update"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := refChangeForClass(tc.class); got != tc.want {
				t.Fatalf("refChangeForClass() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPushAuditOperationUsesClassifiedOperation(t *testing.T) {
	tests := []struct {
		name    string
		classes []gitproxy.ClassifiedCommand
		want    string
	}{
		{name: "empty defaults append", want: string(policy.OpGitPushAppend)},
		{name: "append", classes: []gitproxy.ClassifiedCommand{{Kind: gitproxy.RefUpdateAppend}}, want: string(policy.OpGitPushAppend)},
		{name: "force", classes: []gitproxy.ClassifiedCommand{{Kind: gitproxy.RefUpdateHistoryRewrite}}, want: string(policy.OpGitPushForce)},
		{name: "delete", classes: []gitproxy.ClassifiedCommand{{Kind: gitproxy.RefUpdateRefDelete}}, want: string(policy.OpGitRefDelete)},
		{name: "tag", classes: []gitproxy.ClassifiedCommand{{Kind: gitproxy.RefUpdateTagUpdate}}, want: string(policy.OpGitTagUpdate)},
		{name: "mixed", classes: []gitproxy.ClassifiedCommand{{Kind: gitproxy.RefUpdateAppend}, {Kind: gitproxy.RefUpdateHistoryRewrite}}, want: "git.push"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := pushAuditOperation(tc.classes); got != tc.want {
				t.Fatalf("pushAuditOperation() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseGrantTarget(t *testing.T) {
	tests := []struct {
		target string
		ok     bool
		typ    policy.RepoType
	}{
		{target: "model/acme/repo", ok: true, typ: policy.TypeModel},
		{target: "dataset/acme/repo", ok: true, typ: policy.TypeDataset},
		{target: "space/acme/repo", ok: true, typ: policy.TypeSpace},
		{target: "dataset/acme", ok: false},
		{target: "bucket/acme/repo", ok: false},
		{target: "dataset/acme/../repo", ok: false},
		{target: "dataset//repo", ok: false},
		{target: "dataset/acme/bad repo", ok: false},
		{target: "dataset/acme/*", ok: false},
		{target: "dataset/a?me/repo", ok: false},
		{target: "dataset/acme/repo\x00x", ok: false},
	}
	for _, tc := range tests {
		t.Run(tc.target, func(t *testing.T) {
			rt, ok := parseGrantTarget(tc.target)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && rt.repoType != tc.typ {
				t.Fatalf("repoType = %q, want %q", rt.repoType, tc.typ)
			}
		})
	}
}

func TestNewWithTelegramConfigStartsPoller(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	scp, err := policy.Parse([]byte(emptyPolicyJSON()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(Options{
		Audit:   testAuditRecorder(),
		Context: ctx,
		Config: config.Config{
			HFToken:          testToken,
			Clients:          []config.Client{{Name: "agent", Secret: testSecret}},
			StateDir:         t.TempDir(),
			MaxPackBytes:     25 * 1024 * 1024,
			HFTimeout:        10 * time.Second,
			TelegramBotToken: "telegram_token_value",
			TelegramChatID:   123,
		},
		Scope:           scp,
		UpstreamBaseURL: "http://127.0.0.1:1",
		TelegramBaseURL: "http://127.0.0.1:1",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
}
