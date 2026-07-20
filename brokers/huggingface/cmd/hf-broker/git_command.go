package main

import (
	"github.com/osolmaz/brokerkit/git/client"
)

func huggingFaceGitProvider() gitclient.Provider {
	return gitclient.Provider{
		ID: "huggingface", BrokerName: "hf-broker", EnvPrefix: "HF_BROKER",
		CanonicalPrefixes: []string{"https://huggingface.co/", "ssh://git@hf.co/", "git@hf.co:"},
	}
}

func runGitCommand(command commandContext, args []string) error {
	return gitclient.RunCommand(command.ctx, huggingFaceGitProvider(), args, command.stdout, command.stderr)
}
