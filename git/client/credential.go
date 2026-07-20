package gitclient

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/osolmaz/brokerkit/internal/config/client"
)

const maxCredentialInputBytes = 16 * 1024

// Credential serves Git's credential-helper protocol for one provider.
func Credential(provider Provider, homeDir, action string, stdin io.Reader, stdout io.Writer) error {
	if slices.Contains([]string{"capability", "store", "erase"}, action) {
		return nil
	}
	if action != "get" {
		return errors.New("unsupported credential-helper action")
	}
	return getCredential(provider, homeDir, stdin, stdout)
}

func getCredential(provider Provider, homeDir string, stdin io.Reader, stdout io.Writer) error {
	request, err := readCredentialRequest(stdin)
	if err != nil {
		return err
	}
	client, err := clientconfig.Read(homeDir, provider.BrokerName, provider.EnvPrefix)
	if err != nil {
		writeQuit(stdout)
		return errors.New("broker client configuration is unavailable")
	}
	if client.GitEndpoint == "" {
		writeQuit(stdout)
		return nil
	}
	origin, err := gitOrigin(client.GitEndpoint)
	if err != nil {
		return errors.New("broker Git endpoint is invalid")
	}
	if !credentialMatches(request, origin) {
		return nil
	}
	_, err = fmt.Fprintf(stdout, "username=brokerkit\npassword=%s\n", client.SharedSecret)
	return err
}

func writeQuit(output io.Writer) { _, _ = fmt.Fprintln(output, "quit=true") }

func readCredentialRequest(input io.Reader) (map[string]string, error) {
	limited := io.LimitReader(input, maxCredentialInputBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, errors.New("read credential request")
	}
	if len(data) > maxCredentialInputBytes {
		return nil, errors.New("credential request is too large")
	}
	values := map[string]string{}
	seen := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || seen[key] {
			return nil, errors.New("credential request is malformed")
		}
		values[key] = value
		seen[key] = true
	}
	return values, scanner.Err()
}

func credentialMatches(request map[string]string, origin string) bool {
	parsed, err := url.Parse(origin)
	if err != nil || request["protocol"] != parsed.Scheme {
		return false
	}
	requestHost := request["host"]
	if requestHost == "" || !sameHostPort(requestHost, parsed.Host) {
		return false
	}
	path := request["path"]
	return path != "" && !strings.HasPrefix(path, "/") && !strings.Contains(path, "..")
}

func sameHostPort(left, right string) bool {
	leftHost, leftPort, leftErr := net.SplitHostPort(left)
	rightHost, rightPort, rightErr := net.SplitHostPort(right)
	return leftErr == nil && rightErr == nil && leftPort == rightPort && leftHost == rightHost
}
