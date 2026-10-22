package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/deployment/api"
	"github.com/osolmaz/unyolo/deployment/component"
	deploymentruntime "github.com/osolmaz/unyolo/deployment/runtime"
	"github.com/osolmaz/unyolo/internal/strictjson"
)

func telegramRenderRequest(t *testing.T) (api.RenderRequest, map[string][]byte) {
	t.Helper()
	template, err := os.ReadFile("deployment/profile.json")
	if err != nil {
		t.Fatal(err)
	}
	assets := map[string][]byte{}
	for _, path := range []string{"files/telegram/config.json", "files/telegram/unyolo-telegram.service"} {
		data, err := os.ReadFile("deployment/" + path)
		if err != nil {
			t.Fatal(err)
		}
		assets[path] = data
	}
	request := api.RenderRequest{
		APIVersion: api.RenderAPIVersion, ComponentID: "telegram", OperatingSystem: "linux", Architecture: "amd64",
		Approvers: []api.RenderApprover{
			{ID: "onur", Account: "onur"},
			{ID: "telegram", Account: "unyolo-telegram", Managed: true, Home: "/var/lib/unyolo-telegram"},
		},
		Providers: []string{"github", "sudo"},
		Telegram:  &api.RenderTelegram{ChatID: -100123},
		Profile:   template,
	}
	for _, path := range []string{"files/telegram/config.json", "files/telegram/unyolo-telegram.service"} {
		request.Files = append(request.Files, renderFile(path, assets[path]))
	}
	return request, assets
}

func renderFile(path string, data []byte) api.RenderFile {
	return api.RenderFile{Path: path, SHA256: sha256Digest(data), Data: data}
}

func sha256Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestComponentRendererWritesOwnerConfig(t *testing.T) {
	request, assets := telegramRenderRequest(t)
	var input, output bytes.Buffer
	if err := deploymentruntime.WriteFrame(&input, request); err != nil {
		t.Fatal(err)
	}
	if err := component.ServeRender(&input, &output, componentRenderer{}); err != nil {
		t.Fatal(err)
	}
	var response api.RenderResponse
	if err := deploymentruntime.ReadFrame(&output, &response); err != nil {
		t.Fatal(err)
	}
	var config []byte
	for _, file := range response.Files {
		if file.Path == configAsset {
			config = file.Data
		}
	}
	var rendered ingressConfig
	if err := strictjson.Decode(config, &rendered, true); err != nil {
		t.Fatalf("rendered config = %s: %v", config, err)
	}
	if rendered.TelegramChatID != -100123 || rendered.InboxPath != "/var/lib/unyolo-telegram/state/callbacks.db" ||
		rendered.Routes["g"].OperatorClientFile != "/var/lib/unyolo-telegram/.config/gh-broker/operator.json" ||
		rendered.Routes["s"].OperatorClientFile != "/var/lib/unyolo-telegram/.config/sudo-broker/operator.json" || len(rendered.Routes) != 2 {
		t.Fatalf("rendered config = %+v", rendered)
	}
	var profile component.Profile
	if err := strictjson.Decode(response.Profile, &profile, true); err != nil {
		t.Fatal(err)
	}
	for _, file := range profile.Files {
		if file.ID == "config-json" && file.Source.SHA256 != sha256Digest(config) {
			t.Fatalf("config digest is not bound: %+v", file)
		}
	}
	if string(assets[configAsset]) == string(config) {
		t.Fatal("renderer did not replace the config template")
	}
	slots := make([]string, 0, len(response.SecretPrompts))
	for _, prompt := range response.SecretPrompts {
		slots = append(slots, prompt.Slot)
	}
	if strings.Join(slots, ",") != "telegram-bot-token,telegram-inbox-key" {
		t.Fatalf("secret prompts = %v", slots)
	}
}

func TestComponentRendererRejectsInvalidRequests(t *testing.T) {
	for name, mutate := range map[string]func(*api.RenderRequest){
		"other component":  func(request *api.RenderRequest) { request.ComponentID = "github" },
		"no chat":          func(request *api.RenderRequest) { request.Telegram = nil },
		"no managed owner": func(request *api.RenderRequest) { request.Approvers = request.Approvers[:1] },
		"person as owner": func(request *api.RenderRequest) {
			request.Approvers[1] = api.RenderApprover{ID: "telegram", Account: "onur"}
		},
		"no providers":       func(request *api.RenderRequest) { request.Providers = nil },
		"unknown provider":   func(request *api.RenderRequest) { request.Providers = []string{"gitlab"} },
		"invalid template":   func(request *api.RenderRequest) { request.Profile = []byte(`{"api_version":"x","extra":1}`) },
		"invalid validation": func(request *api.RenderRequest) { request.OperatingSystem = "" },
	} {
		t.Run(name, func(t *testing.T) {
			request, assets := telegramRenderRequest(t)
			request.Approvers = append([]api.RenderApprover(nil), request.Approvers...)
			mutate(&request)
			if _, err := (componentRenderer{}).Render(request, request.Profile, assets); err == nil {
				t.Fatal("invalid telegram render was accepted")
			}
		})
	}
}

func TestComponentConfigOwnsOnlyTelegramPaths(t *testing.T) {
	config := componentConfig()
	if len(config.AllowedAccounts) != 0 || len(config.AllowedGroups) != 0 || config.ComponentID != componentID {
		t.Fatalf("component config = %+v", config)
	}
	for _, path := range config.AllowedPaths {
		if !strings.HasPrefix(path, "/etc/unyolo-telegram") && !strings.HasPrefix(path, "/var/lib/unyolo-telegram/") &&
			path != "/etc/systemd/system/unyolo-telegram.service" {
			t.Fatalf("component owns %q", path)
		}
	}
}

func TestReleaseDeploymentProfileMatchesTelegramAdapter(t *testing.T) {
	profile, err := os.ReadFile("deployment/profile.json")
	if err != nil {
		t.Fatal(err)
	}
	request := api.Request{
		APIVersion: api.APIVersion, Action: api.ActionValidate, DeploymentDigest: "sha256:" + strings.Repeat("a", 64),
		ComponentID: componentID, Profile: profile,
		Operators: []api.OperatorBinding{{ID: "telegram", UnixUser: componentAccount, Home: "/var/lib/unyolo-telegram"}},
	}
	var input, output bytes.Buffer
	if err := deploymentruntime.WriteFrame(&input, request); err != nil {
		t.Fatal(err)
	}
	if err := component.Serve(t.Context(), &input, &output, componentConfig()); err != nil {
		t.Fatal(err)
	}
	var response api.Response
	if err := deploymentruntime.ReadFrame(&output, &response); err != nil || response.Status != "valid" {
		t.Fatalf("profile response = %+v, %v", response, err)
	}
}
