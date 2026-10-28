package gitclient

import (
	"reflect"
	"strings"
	"testing"
)

func TestCredentialRequestAdvisoryArrays(t *testing.T) {
	scalar := "protocol=http\nhost=127.0.0.1:12345\npath=fixture/repo.git\n"
	want := map[string]string{"protocol": "http", "host": "127.0.0.1:12345", "path": "fixture/repo.git"}
	for _, arrays := range []string{
		"capability[]=authtype\ncapability[]=state\nwwwauth[]=Basic realm=fixture\nwwwauth[]=Bearer realm=fixture\n",
		"capability[]=state\ncapability[]=\ncapability[]=authtype\nwwwauth[]=\nwwwauth[]=Basic\nwwwauth[]=\n",
	} {
		got, err := readCredentialRequest(strings.NewReader(arrays + scalar + "\n"))
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v, %v; want %#v, nil", got, err, want)
		}
	}
}

func TestCredentialRequestMalformedAndBounded(t *testing.T) {
	for name, input := range map[string]string{
		"duplicate protocol":          "protocol=http\nprotocol=http\n",
		"conflicting host":            "host=127.0.0.1:1\nhost=127.0.0.1:2\n",
		"duplicate path":              "path=fixture/repo.git\npath=fixture/repo.git\n",
		"duplicate unknown scalar":    "unknown=x\nunknown=y\n",
		"unrecognized repeated array": "unknown[]=x\nunknown[]=y\n",
		"missing equals":              "capability[]\n",
		"empty key":                   "=value\n",
		"NUL array key":               "capability[]\x00=x\n",
		"NUL ignored array value":     "wwwauth[]=Basic\x00fixture\n",
		"oversize advisory list":      "capability[]=" + strings.Repeat("x", maxCredentialInputBytes) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := readCredentialRequest(strings.NewReader(input)); err == nil || got != nil {
				t.Fatalf("got %#v, %v; want nil and refusal", got, err)
			}
		})
	}
	input := "capability[]=" + strings.Repeat("x", maxCredentialInputBytes-len("capability[]=\n")) + "\n"
	if _, err := readCredentialRequest(strings.NewReader(input)); err != nil {
		t.Fatalf("exact input bound refused: %v", err)
	}
}
