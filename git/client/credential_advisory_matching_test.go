package gitclient

import (
	"strings"
	"testing"

	clientconfig "github.com/osolmaz/unyolo/internal/config/client"
)

func TestCredentialAdvisoriesDoNotChangeOriginMatching(t *testing.T) {
	home := t.TempDir()
	const secret = "synthetic-origin-match-canary"
	if _, err := clientconfig.Write(clientconfig.Config{BrokerName: "gh-broker", EnvPrefix: "GH_BROKER", ClientID: "fixture", Endpoint: "unix:///unused/agent.sock", GitEndpoint: "tcp://127.0.0.1:32191", Secret: secret, HomeDir: home}); err != nil {
		t.Fatal(err)
	}
	provider := Provider{ID: "github", BrokerName: "gh-broker", EnvPrefix: "GH_BROKER"}
	for _, test := range []struct {
		name, protocol, host, path string
		matches                    bool
	}{
		{"matching", "http", "127.0.0.1:32191", "fixture/repo.git", true},
		{"scheme", "https", "127.0.0.1:32191", "fixture/repo.git", false},
		{"host", "http", "other.invalid:32191", "fixture/repo.git", false},
		{"port", "http", "127.0.0.1:32192", "fixture/repo.git", false},
		{"no_path", "http", "127.0.0.1:32191", "", false},
		{"traversal", "http", "127.0.0.1:32191", "../repo.git", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := "capability[]=authtype\ncapability[]=state\nwwwauth[]=Basic\nwwwauth[]=Bearer\nprotocol=" + test.protocol + "\nhost=" + test.host + "\npath=" + test.path + "\n\n"
			var output strings.Builder
			err := Credential(provider, home, "get", strings.NewReader(input), &output)
			want := ""
			if test.matches {
				want = "username=unyolo\npassword=" + secret + "\n"
			}
			if err != nil || output.String() != want {
				t.Fatalf("credential match=%v outputMatches=%v err=%v", test.matches, output.String() == want, err)
			}
		})
	}
}
