package isolation

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	bkdoctor "github.com/osolmaz/brokerkit/internal/host/doctor"
)

// WriteText writes the human-readable report.
func WriteText(w io.Writer, report Report) error {
	if _, err := fmt.Fprintln(w, strings.ToUpper(string(report.Status))); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	if err := writeTextChecks(w, report.Checks); err != nil {
		return err
	}
	return writeTextCredentials(w, report.Credentials)
}

func writeTextChecks(w io.Writer, checks []Check) error {
	for _, status := range []CheckStatus{CheckFail, CheckUnknown, CheckWarn, CheckPass} {
		for _, check := range checks {
			if check.Status != status {
				continue
			}
			if _, err := fmt.Fprintf(w, "- %s %s: %s\n", check.Status, check.Name, check.Message); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeTextCredentials(w io.Writer, credentials []bkdoctor.CredentialStatus) error {
	for _, credential := range credentials {
		if _, err := fmt.Fprintf(w, "- credential %s: source=%s age=%s expiry=%s expires_at=%s rotation=%s revocation=%s\n",
			credential.Class, credential.Source, credential.Age, credential.Expiry, credential.ExpiresAt, credential.Rotation, credential.Revocation); err != nil {
			return err
		}
	}
	return nil
}

// WriteJSON writes the machine-readable report.
func WriteJSON(w io.Writer, report Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// ExitCode returns the command exit code for the report.
func ExitCode(status Status) int {
	return bkdoctor.ExitCode(status)
}

func add(report *Report, status CheckStatus, name, message string) {
	report.Checks = append(report.Checks, Check{Status: status, Name: name, Message: message})
}
