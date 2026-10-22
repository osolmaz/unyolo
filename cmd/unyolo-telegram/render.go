package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"path/filepath"

	"github.com/osolmaz/unyolo/approval/notifier/telegram"
	"github.com/osolmaz/unyolo/deployment/api"
	"github.com/osolmaz/unyolo/deployment/component"
	clientconfig "github.com/osolmaz/unyolo/internal/config/client"
	"github.com/osolmaz/unyolo/internal/strictjson"
)

const (
	componentID        = "telegram"
	componentAccount   = "unyolo-telegram"
	componentConfigDir = "/etc/unyolo-telegram"
	componentStateDir  = "/var/lib/unyolo-telegram/state"
	configAsset        = "files/telegram/config.json"
)

// routeProviders binds each card route to the provider component and the
// broker whose operator client document the owner reads.
var routeProviders = map[string]struct{ route, broker string }{
	"github":      {telegram.RouteGitHub, "gh-broker"},
	"huggingface": {telegram.RouteHuggingFace, "hf-broker"},
	"sudo":        {telegram.RouteSudo, "sudo-broker"},
}

// componentRenderer renders the Telegram deployment component: the owner's
// configuration for the chat and for every installed provider.
type componentRenderer struct{}

func (componentRenderer) Render(request api.RenderRequest, template []byte, assets map[string][]byte) (api.RenderResponse, error) {
	if err := request.Validate(); err != nil {
		return api.RenderResponse{}, err
	}
	if request.ComponentID != componentID || request.Telegram == nil {
		return api.RenderResponse{}, errors.New("telegram render requires the telegram component and its chat")
	}
	home, err := ownerHome(request.Approvers)
	if err != nil {
		return api.RenderResponse{}, err
	}
	routes, err := ownerRoutes(request.Providers, home)
	if err != nil {
		return api.RenderResponse{}, err
	}
	var profile component.Profile
	if err := strictjson.Decode(template, &profile, true); err != nil {
		return api.RenderResponse{}, fmt.Errorf("decode telegram profile template: %w", err)
	}
	config := ingressConfig{
		TelegramBotTokenFile: filepath.Join(componentConfigDir, "telegram-bot-token"),
		TelegramChatID:       request.Telegram.ChatID,
		InboxPath:            filepath.Join(componentStateDir, "callbacks.db"),
		InboxKeyFile:         filepath.Join(componentConfigDir, "inbox-key"),
		Routes:               routes,
	}
	if err := validateIngressConfig(config); err != nil {
		return api.RenderResponse{}, err
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return api.RenderResponse{}, err
	}
	rendered := maps.Clone(assets)
	if rendered == nil {
		rendered = map[string][]byte{}
	}
	rendered[configAsset] = append(data, '\n')
	return component.FinishRender(request, profile, rendered)
}

// ownerHome returns the home of the managed Telegram approver. The owner reads
// each provider's operator client document from that home.
func ownerHome(approvers []api.RenderApprover) (string, error) {
	for _, approver := range approvers {
		if approver.ID == componentID {
			if !approver.Managed || approver.Account != componentAccount {
				return "", errors.New("telegram approver must be the managed unyolo-telegram account")
			}
			return approver.Home, nil
		}
	}
	return "", errors.New("telegram render requires the managed telegram approver")
}

func ownerRoutes(providers []string, home string) (map[string]routeConfig, error) {
	if len(providers) == 0 {
		return nil, errors.New("telegram render requires at least one provider")
	}
	routes := make(map[string]routeConfig, len(providers))
	for _, provider := range providers {
		binding, supported := routeProviders[provider]
		if !supported {
			return nil, fmt.Errorf("telegram approval cards do not support provider %q", provider)
		}
		path, err := clientconfig.OperatorPath(home, binding.broker)
		if err != nil {
			return nil, err
		}
		routes[binding.route] = routeConfig{OperatorClientFile: path}
	}
	return routes, nil
}
