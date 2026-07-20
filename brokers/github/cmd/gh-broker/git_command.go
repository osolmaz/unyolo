package main

import (
	"context"
	"io"

	"github.com/osolmaz/brokerkit/git/client"
)

func githubGitProvider() gitclient.Provider {
	return gitclient.Provider{
		ID: "github", BrokerName: "gh-broker", EnvPrefix: "GH_BROKER",
		CanonicalPrefixes: []string{"https://github.com/", "ssh://git@github.com/", "git@github.com:"},
	}
}

func runGitCommand(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	return gitclient.RunCommand(ctx, githubGitProvider(), args, stdout, stderr)
}
