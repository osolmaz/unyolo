package main

import (
	"fmt"
	"os"

	"github.com/osolmaz/brokerkit/git/client"
)

var providers = map[string]gitclient.Provider{
	"github": {
		ID: "github", BrokerName: "gh-broker", EnvPrefix: "GH_BROKER",
		CanonicalPrefixes: []string{"https://github.com/", "ssh://git@github.com/", "git@github.com:"},
	},
	"huggingface": {
		ID: "huggingface", BrokerName: "hf-broker", EnvPrefix: "HF_BROKER",
		CanonicalPrefixes: []string{"https://huggingface.co/", "ssh://git@hf.co/", "git@hf.co:"},
	},
}

func main() {
	providerName, action, err := gitclient.ParseCredentialArgs(os.Args[1:])
	provider, found := providers[providerName]
	if err == nil && !found {
		err = fmt.Errorf("unknown provider %q", providerName)
	}
	if err == nil {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			err = homeErr
		} else {
			err = gitclient.Credential(provider, home, action, os.Stdin, os.Stdout)
		}
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "git-credential-brokerkit:", err)
		os.Exit(1)
	}
}
