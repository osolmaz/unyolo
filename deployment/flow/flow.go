// Package flow defines the renderer-neutral guided setup contract.
package flow

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	APIVersion    = "unyolo.io/setup-flow/v1"
	MaxSteps      = 256
	MaxOptions    = 512
	MaxTextBytes  = 16 * 1024
	MaxTitleBytes = 512
)

// StepType is one closed setup interaction kind.
type StepType string

const (
	StepNote        StepType = "note"
	StepSelect      StepType = "select"
	StepMultiSelect StepType = "multiselect"
	StepText        StepType = "text"
	StepSecret      StepType = "secret"
	StepFile        StepType = "file"
	StepConfirm     StepType = "confirm"
	StepDeviceCode  StepType = "device_code"
	StepProgress    StepType = "progress"
	StepOpenURL     StepType = "open_url"
	StepReview      StepType = "review"
)

var stepIDPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$`)

// Option is one stable select value and its human description.
type Option struct {
	Value string `json:"value"`
	Label string `json:"label"`
	Hint  string `json:"hint,omitempty"`
}

// Validation contains bounded renderer-neutral input constraints.
type Validation struct {
	MinLength int    `json:"min_length,omitempty"`
	MaxLength int    `json:"max_length,omitempty"`
	Pattern   string `json:"pattern,omitempty"`
}

// Navigation describes safe movement through completed steps.
type Navigation struct {
	CanGoBack    bool `json:"can_go_back,omitempty"`
	CanGoForward bool `json:"can_go_forward,omitempty"`
}

// Step is one adapter-requested interaction.
type Step struct {
	APIVersion       string     `json:"api_version"`
	ID               string     `json:"id"`
	Type             StepType   `json:"type"`
	Title            string     `json:"title"`
	Help             string     `json:"help,omitempty"`
	Required         bool       `json:"required,omitempty"`
	Default          string     `json:"default,omitempty"`
	DefaultValues    []string   `json:"default_values,omitempty"`
	Options          []Option   `json:"options,omitempty"`
	Searchable       bool       `json:"searchable,omitempty"`
	SafeConfirmation bool       `json:"safe_confirmation,omitempty"`
	Validation       Validation `json:"validation,omitempty"`
	Navigation       Navigation `json:"navigation,omitempty"`
	URL              string     `json:"url,omitempty"`
	Code             string     `json:"code,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
}

// Answer is a nonsecret response. Secret steps set Supplied and omit values.
type Answer struct {
	APIVersion string   `json:"api_version"`
	StepID     string   `json:"step_id"`
	Values     []string `json:"values,omitempty"`
	Confirmed  *bool    `json:"confirmed,omitempty"`
	Supplied   bool     `json:"supplied,omitempty"`
}

// Prompt describes one text-like question to a renderer.
type Prompt struct {
	Message      string
	Description  string
	InitialValue string
	Placeholder  string
	Required     bool
	Navigation   Navigation
	Validate     func(string) error
}

// SelectPrompt describes one selection question.
type SelectPrompt struct {
	Message       string
	Description   string
	Options       []Option
	InitialValue  string
	InitialValues []string
	Searchable    bool
	Required      bool
	Navigation    Navigation
}

// ConfirmPrompt describes one explicit confirmation.
type ConfirmPrompt struct {
	Message     string
	Description string
	Affirmative string
	Negative    string
	Initial     bool
	Safe        bool
	Navigation  Navigation
}

// DeviceCodePrompt is a structured temporary provider code.
type DeviceCodePrompt struct {
	Title     string
	Message   string
	Code      string
	ExpiresAt *time.Time
}

// Progress is an active inline progress indicator.
type Progress interface {
	Update(message string)
	Stop(message string)
	Fail(message string)
}

// SetupPrompter separates guided setup decisions from terminal presentation.
type SetupPrompter interface {
	Intro(context.Context, string) error
	Outro(context.Context, string) error
	Note(context.Context, string, string) error
	Select(context.Context, SelectPrompt) (string, error)
	MultiSelect(context.Context, SelectPrompt) ([]string, error)
	Text(context.Context, Prompt) (string, error)
	Secret(context.Context, Prompt) ([]byte, error)
	Confirm(context.Context, ConfirmPrompt) (bool, error)
	DeviceCode(context.Context, DeviceCodePrompt) error
	OpenURL(context.Context, string) error
	Progress(string) Progress
	Close() error
}

// CancelledError identifies explicit cancellation or terminal EOF.
type CancelledError struct{ Cause error }

func (e CancelledError) Error() string { return "setup cancelled" }
func (e CancelledError) Unwrap() error { return e.Cause }

// NavigationError requests a safe step transition.
type NavigationError struct{ Direction string }

func (e NavigationError) Error() string { return "setup navigate " + e.Direction }

// BackSentinel is the reserved option value used by renderers to expose
// "Go back" as an inline choice. When a Select or Confirm returns this
// value, the caller receives [NavigationError] with Direction "back".
const BackSentinel = "__setup_back__"

// EditSentinel is the reserved option value used by review-style Confirm
// prompts to expose "Edit". When a Confirm returns this value, the caller
// receives [NavigationError] with Direction "edit".
const EditSentinel = "__setup_edit__"

// Validate verifies a closed setup-flow step.
func (s Step) Validate() error {
	if s.APIVersion != APIVersion {
		return fmt.Errorf("unsupported setup-flow API %q", s.APIVersion)
	}
	if !stepIDPattern.MatchString(s.ID) {
		return errors.New("setup step ID is invalid")
	}
	if strings.TrimSpace(s.Title) == "" || len(s.Title) > MaxTitleBytes || len(s.Help) > MaxTextBytes {
		return errors.New("setup step title or help text is invalid")
	}
	if !validStepType(s.Type) {
		return fmt.Errorf("setup step type %q is invalid", s.Type)
	}
	if err := validateOptions(s); err != nil {
		return err
	}
	if err := validateInputConstraints(s); err != nil {
		return err
	}
	return validateTransientFields(s)
}

func validStepType(value StepType) bool {
	return slices.Contains([]StepType{
		StepNote, StepSelect, StepMultiSelect, StepText, StepSecret, StepFile,
		StepConfirm, StepDeviceCode, StepProgress, StepOpenURL, StepReview,
	}, value)
}

//nolint:cyclop // Option constraints differ by the closed setup step kind.
func validateOptions(step Step) error {
	hasOptions := step.Type == StepSelect || step.Type == StepMultiSelect
	if !hasOptions && (len(step.Options) > 0 || len(step.DefaultValues) > 0 || step.Searchable) {
		return errors.New("setup step has selection fields for a non-selection type")
	}
	if !hasOptions {
		return nil
	}
	if len(step.Options) == 0 || len(step.Options) > MaxOptions {
		return errors.New("selection step must contain a bounded nonempty option list")
	}
	seen := map[string]bool{}
	for _, option := range step.Options {
		if strings.TrimSpace(option.Value) == "" || strings.TrimSpace(option.Label) == "" ||
			len(option.Value) > MaxTitleBytes || len(option.Label) > MaxTitleBytes || len(option.Hint) > MaxTitleBytes || seen[option.Value] {
			return errors.New("selection option is invalid or duplicated")
		}
		seen[option.Value] = true
	}
	return nil
}

func validateInputConstraints(step Step) error {
	validation := step.Validation
	if validation.MinLength < 0 || validation.MaxLength < 0 || validation.MaxLength > MaxTextBytes ||
		(validation.MaxLength > 0 && validation.MinLength > validation.MaxLength) {
		return errors.New("setup input length constraint is invalid")
	}
	if validation.Pattern != "" {
		if len(validation.Pattern) > MaxTitleBytes {
			return errors.New("setup input pattern is too large")
		}
		if _, err := regexp.Compile(validation.Pattern); err != nil {
			return errors.New("setup input pattern is invalid")
		}
	}
	return nil
}

//nolint:cyclop // Secret-bearing fields are rejected explicitly for every persisted step kind.
func validateTransientFields(step Step) error {
	switch step.Type {
	case StepOpenURL:
		return validateHTTPS(step.URL)
	case StepDeviceCode:
		if strings.TrimSpace(step.Code) == "" || len(step.Code) > 256 || step.ExpiresAt == nil {
			return errors.New("device code step is incomplete")
		}
	case StepSecret:
		if step.Default != "" {
			return errors.New("secret step must not have a default value")
		}
	default:
		if step.URL != "" || step.Code != "" || step.ExpiresAt != nil {
			return errors.New("setup step has transient fields for the wrong type")
		}
	}
	return nil
}

func validateHTTPS(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return errors.New("setup URL must be an HTTPS URL without user information")
	}
	return nil
}
