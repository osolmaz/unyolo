package credentialprofile

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestEmbeddedRequirementsAreCanonicalAndValid(t *testing.T) {
	profile, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if profile.ProfileID != "hf-broker-complete-v1" {
		t.Fatalf("unexpected profile ID %q", profile.ProfileID)
	}
	raw, err := JSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(raw, []byte("\n")) {
		t.Fatal("canonical requirements must end with a newline")
	}
	var decoded Requirements
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := Validate(decoded); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(decoded.PersonalPermissions, "resourceGroup.write") {
		t.Fatal("resourceGroup.write is organization-scoped and must not be requested for a user")
	}
	if !slices.Contains(decoded.OrganizationPermissions, "resourceGroup.write") {
		t.Fatal("organization permissions must include resourceGroup.write")
	}
}

func TestValidateRejectsInvalidProfiles(t *testing.T) {
	valid, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Requirements)
		want   string
	}{
		{name: "version", mutate: func(value *Requirements) { value.Version = 2 }, want: "version"},
		{name: "profile ID", mutate: func(value *Requirements) { value.ProfileID = "" }, want: "profile_id"},
		{name: "URL", mutate: func(value *Requirements) { value.TokenFormURL = "http://example.test" }, want: "token_form_url"},
		{name: "token type", mutate: func(value *Requirements) { value.TokenType = "write" }, want: "token_type"},
		{name: "gated", mutate: func(value *Requirements) { value.RequiresGatedRepositories = false }, want: "gated"},
		{name: "empty", mutate: func(value *Requirements) { value.PersonalPermissions = nil }, want: "must not be empty"},
		{name: "unsorted", mutate: func(value *Requirements) {
			value.GlobalPermissions = []string{"post.write", "discussion.write"}
		}, want: "must be sorted"},
		{name: "duplicate", mutate: func(value *Requirements) {
			value.GlobalPermissions = []string{"post.write", "post.write"}
		}, want: "duplicate"},
		{name: "invalid permission", mutate: func(value *Requirements) {
			value.GlobalPermissions = []string{" discussion.write", "post.write"}
		}, want: "invalid permission"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := clone(valid)
			test.mutate(&candidate)
			if err := Validate(candidate); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want containing %q", err, test.want)
			}
		})
	}
}
