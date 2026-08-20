// Package operationcli presents Agent V1 operation lifecycles to CLI users.
package operationcli

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	agentv1 "github.com/osolmaz/unyolo/agent/v1"
)

const (
	maxOperationIDBytes  = 128
	maxCommandTokens     = 16
	maxCommandTokenBytes = 256
)

// Intent identifies what the CLI command was asked to do.
type Intent uint8

const (
	IntentSubmit Intent = iota + 1
	IntentSubmitWait
	IntentGet
	IntentWait
	IntentCancel
)

// Presentation is the safe lifecycle guidance and exit disposition for one
// successfully returned Agent V1 operation.
type Presentation struct {
	Notice        string
	CommandFailed bool
}

// Describe derives CLI guidance from command intent and the authoritative
// Agent V1 operation state. waitCommand must end with the same operation ID.
func Describe(intent Intent, operation agentv1.Operation, waitCommand []string) (Presentation, error) {
	if !validIntent(intent) {
		return Presentation{}, errors.New("operation CLI intent is invalid")
	}
	if !operation.State.Valid() {
		return Presentation{}, errors.New("operation state is invalid")
	}
	if err := validateDisplayValue(operation.ID, maxOperationIDBytes); err != nil {
		return Presentation{}, errors.New("operation ID is unsafe to display")
	}
	if intent == IntentCancel {
		if !operation.State.Terminal() {
			return Presentation{}, errors.New("cancel returned a nonterminal operation")
		}
		return describeCancel(operation), nil
	}
	if !operation.State.Terminal() {
		command, err := renderWaitCommand(waitCommand, operation.ID)
		if err != nil {
			return Presentation{}, err
		}
		return Presentation{
			Notice: fmt.Sprintf(
				"Operation %s is %s and is not complete.\nDo not report the requested action as completed.\nNext: %s\n",
				operation.ID, operation.State, command,
			),
			CommandFailed: intent == IntentSubmitWait || intent == IntentWait,
		}, nil
	}
	if operation.State == agentv1.StateSucceeded {
		return Presentation{
			Notice:        fmt.Sprintf("Operation %s succeeded. The requested action completed. Use the operation output as the authoritative receipt.\n", operation.ID),
			CommandFailed: false,
		}, nil
	}
	return Presentation{
		Notice: fmt.Sprintf(
			"Operation %s is %s. The requested action did not complete. Do not report it as successful. See the operation output for safe details.\n",
			operation.ID, operation.State,
		),
		CommandFailed: intent != IntentGet,
	}, nil
}

// WaitTimeoutArgument formats an existing positive wait timeout for a safe
// lifecycle recovery command.
func WaitTimeoutArgument(timeout time.Duration) string {
	if timeout > 0 && timeout%time.Hour == 0 {
		return fmt.Sprintf("%dh", timeout/time.Hour)
	}
	if timeout > 0 && timeout%time.Minute == 0 {
		return fmt.Sprintf("%dm", timeout/time.Minute)
	}
	return timeout.String()
}

func validIntent(intent Intent) bool {
	return slices.Contains([]Intent{IntentSubmit, IntentSubmitWait, IntentGet, IntentWait, IntentCancel}, intent)
}

func describeCancel(operation agentv1.Operation) Presentation {
	switch operation.State {
	case agentv1.StateCanceled:
		return Presentation{Notice: fmt.Sprintf(
			"Operation %s was canceled. The cancellation command completed; the requested action did not complete.\n",
			operation.ID,
		)}
	case agentv1.StateSucceeded:
		return Presentation{Notice: fmt.Sprintf(
			"Operation %s had already succeeded. The requested action completed before cancellation; the cancel command made no change.\n",
			operation.ID,
		)}
	default:
		return Presentation{Notice: fmt.Sprintf(
			"Operation %s was already %s. The requested action did not complete; the cancel command made no change.\n",
			operation.ID, operation.State,
		)}
	}
}

func renderWaitCommand(tokens []string, operationID string) (string, error) {
	if len(tokens) == 0 || len(tokens) > maxCommandTokens || tokens[len(tokens)-1] != operationID {
		return "", errors.New("wait command must end with the operation ID")
	}
	rendered := make([]string, 0, len(tokens))
	for _, token := range tokens {
		if err := validateDisplayValue(token, maxCommandTokenBytes); err != nil {
			return "", errors.New("wait command contains an unsafe token")
		}
		rendered = append(rendered, quoteShellToken(token))
	}
	return strings.Join(rendered, " "), nil
}

func validateDisplayValue(value string, maxBytes int) error {
	if value == "" || len(value) > maxBytes {
		return errors.New("display value has invalid length")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return errors.New("display value contains a control character")
		}
	}
	return nil
}

func quoteShellToken(value string) string {
	if strings.IndexFunc(value, func(character rune) bool {
		return !safeShellCharacter(character)
	}) == -1 {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func safeShellCharacter(character rune) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9' ||
		strings.ContainsRune("_./:@%+=,-", character)
}
