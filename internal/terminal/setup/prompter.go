// Package setup implements BrokerKit's inline guided setup renderer.
package setup

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"github.com/osolmaz/brokerkit/deployment/flow"
	"golang.org/x/term"
)

const (
	ansiReset  = "\x1b[0m"
	ansiAccent = "\x1b[38;5;39m"
	ansiMuted  = "\x1b[38;5;244m"
	ansiGreen  = "\x1b[38;5;42m"
	ansiRed    = "\x1b[38;5;196m"
)

var controlPattern = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)

// Options configures one terminal renderer.
type Options struct {
	Input      io.Reader
	Output     io.Writer
	Accessible bool
	NoOpen     bool
	OpenURL    func(context.Context, string) error
	Width      int
}

// Prompter is an inline Huh-backed SetupPrompter.
type Prompter struct {
	input      io.Reader
	output     io.Writer
	accessible bool
	color      bool
	noOpen     bool
	openURL    func(context.Context, string) error
	width      int
	mu         sync.Mutex
	progress   map[*indicator]struct{}
	closed     bool
}

// New constructs a terminal prompter without mutating terminal state.
func New(options Options) *Prompter {
	input, output := options.Input, options.Output
	if input == nil {
		input = os.Stdin
	}
	if output == nil {
		output = os.Stdout
	}
	accessible := options.Accessible || os.Getenv("BROKERKIT_ACCESSIBLE") == "1"
	color := colorEnabled(output)
	width := options.Width
	if width <= 0 {
		width = terminalWidth(output)
	}
	return &Prompter{
		input: input, output: output, accessible: accessible, color: color,
		noOpen: options.NoOpen, openURL: options.OpenURL, width: width,
		progress: map[*indicator]struct{}{},
	}
}

// Intro starts one connected guide.
func (p *Prompter) Intro(_ context.Context, title string) error {
	return p.line(p.paint(ansiAccent, "┌  "+safeText(title)))
}

// Outro closes the guide.
func (p *Prompter) Outro(_ context.Context, message string) error {
	return p.line(p.paint(ansiGreen, "└  "+safeText(message)))
}

// Note renders explanatory text as a guide section.
func (p *Prompter) Note(_ context.Context, message, title string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return errors.New("setup renderer is closed")
	}
	if title != "" {
		if _, err := fmt.Fprintln(p.output, p.paint(ansiAccent, "│  "+safeText(title))); err != nil {
			return err
		}
	}
	for _, line := range wrap(safeText(message), max(20, p.width-4)) {
		if _, err := fmt.Fprintln(p.output, p.paint(ansiMuted, "│  "+line)); err != nil {
			return err
		}
	}
	return nil
}

// Select asks for one value.
func (p *Prompter) Select(ctx context.Context, prompt flow.SelectPrompt) (string, error) {
	value := prompt.InitialValue
	options := huhOptions(prompt.Options)
	field := huh.NewSelect[string]().
		Title(safeText(prompt.Message)).
		Description(p.description(prompt.Description, prompt.Navigation)).
		Options(options...).
		Value(&value).
		Filtering(prompt.Searchable).
		Height(selectHeight(len(options)))
	if err := p.runForm(ctx, field); err != nil {
		return "", err
	}
	return value, nil
}

// MultiSelect asks for zero or more stable values.
func (p *Prompter) MultiSelect(ctx context.Context, prompt flow.SelectPrompt) ([]string, error) {
	values := append([]string(nil), prompt.InitialValues...)
	options := huhOptions(prompt.Options)
	field := huh.NewMultiSelect[string]().
		Title(safeText(prompt.Message)).
		Description(p.description(prompt.Description, prompt.Navigation)).
		Options(options...).
		Value(&values).
		Filtering(prompt.Searchable).
		Height(selectHeight(len(options)))
	if prompt.Required {
		field.Validate(func(values []string) error {
			if len(values) == 0 {
				return errors.New("select at least one option")
			}
			return nil
		})
	}
	if err := p.runForm(ctx, field); err != nil {
		return nil, err
	}
	return values, nil
}

// Text asks for a validated nonsecret value.
func (p *Prompter) Text(ctx context.Context, prompt flow.Prompt) (string, error) {
	value := prompt.InitialValue
	field := huh.NewInput().
		Title(safeText(prompt.Message)).
		Description(p.description(prompt.Description, prompt.Navigation)).
		Placeholder(safeText(prompt.Placeholder)).
		Value(&value).
		CharLimit(flow.MaxTextBytes).
		Validate(promptValidator(prompt))
	if err := p.runForm(ctx, field); err != nil {
		return "", err
	}
	return value, nil
}

// Secret reads a secret without echoing content or preserving its length.
//
//nolint:cyclop // Secret entry keeps accessible, interactive, cancellation, and fixed-mask paths together.
func (p *Prompter) Secret(ctx context.Context, prompt flow.Prompt) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, flow.CancelledError{Cause: err}
	}
	if err := p.line(p.paint(ansiAccent, "│  "+safeText(prompt.Message))); err != nil {
		return nil, err
	}
	if prompt.Description != "" {
		if err := p.line(p.paint(ansiMuted, "│  "+safeText(prompt.Description))); err != nil {
			return nil, err
		}
	}
	var secret []byte
	if file, ok := p.input.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		value, err := term.ReadPassword(int(file.Fd()))
		if err != nil {
			return nil, flow.CancelledError{Cause: err}
		}
		secret = value
		_, _ = fmt.Fprintln(p.output)
	} else {
		value, err := bufio.NewReader(io.LimitReader(p.input, flow.MaxTextBytes+1)).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		secret = []byte(strings.TrimSuffix(strings.TrimSuffix(value, "\n"), "\r"))
	}
	if len(secret) > flow.MaxTextBytes {
		clear(secret)
		return nil, errors.New("secret exceeds size limit")
	}
	if err := promptValidator(prompt)(string(secret)); err != nil {
		clear(secret)
		return nil, err
	}
	if err := p.line(p.paint(ansiMuted, "│  configured")); err != nil {
		clear(secret)
		return nil, err
	}
	return secret, nil
}

// Confirm asks for an explicit safe-default confirmation.
func (p *Prompter) Confirm(ctx context.Context, prompt flow.ConfirmPrompt) (bool, error) {
	value := prompt.Initial
	if prompt.Safe {
		value = false
	}
	field := huh.NewConfirm().
		Title(safeText(prompt.Message)).
		Description(p.description(prompt.Description, prompt.Navigation)).
		Affirmative("Yes").
		Negative("No").
		Inline(false).
		Value(&value)
	if err := p.runForm(ctx, field); err != nil {
		return false, err
	}
	return value, nil
}

// DeviceCode presents a temporary provider code without retaining it.
func (p *Prompter) DeviceCode(ctx context.Context, prompt flow.DeviceCodePrompt) error {
	message := prompt.Message + "\nCode: " + prompt.Code
	if prompt.ExpiresAt != nil {
		message += "\nExpires: " + prompt.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return p.Note(ctx, message, prompt.Title)
}

// OpenURL opens an HTTPS URL after the flow has shown its purpose.
func (p *Prompter) OpenURL(ctx context.Context, value string) error {
	if p.noOpen || p.openURL == nil {
		return p.Note(ctx, value, "Open this URL")
	}
	return p.openURL(ctx, value)
}

// Progress starts one width-bounded inline indicator.
func (p *Prompter) Progress(label string) flow.Progress {
	indicator := newIndicator(p, label)
	p.mu.Lock()
	if !p.closed {
		p.progress[indicator] = struct{}{}
	}
	p.mu.Unlock()
	indicator.start()
	return indicator
}

// Close stops progress and restores cursor visibility.
func (p *Prompter) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	active := make([]*indicator, 0, len(p.progress))
	for item := range p.progress {
		active = append(active, item)
	}
	p.mu.Unlock()
	for _, item := range active {
		item.stop("", false)
	}
	if p.color {
		_, err := fmt.Fprint(p.output, ansiReset+"\x1b[?25h")
		return err
	}
	return nil
}

func (p *Prompter) runForm(ctx context.Context, field huh.Field) error {
	form := huh.NewForm(huh.NewGroup(field)).
		WithAccessible(p.accessible).
		WithTheme(brokerKitTheme(p.color)).
		WithInput(p.input).
		WithOutput(p.output).
		WithShowHelp(true).
		WithShowErrors(true)
	if p.width > 0 {
		form.WithWidth(p.width)
	}
	if err := form.RunWithContext(ctx); err != nil {
		if errors.Is(err, huh.ErrUserAborted) || errors.Is(err, context.Canceled) {
			return flow.CancelledError{Cause: err}
		}
		return err
	}
	return nil
}

func brokerKitTheme(color bool) huh.Theme {
	return huh.ThemeFunc(func(isDark bool) *huh.Styles {
		if !color {
			return huh.ThemeBase(isDark)
		}
		styles := huh.ThemeCharm(isDark)
		accent := lipgloss.Color("#2EA8FF")
		muted := lipgloss.Color("#7C8798")
		success := lipgloss.Color("#20C997")
		danger := lipgloss.Color("#FF5C5C")
		styles.Focused.Base = styles.Focused.Base.BorderForeground(accent)
		styles.Focused.Title = styles.Focused.Title.Foreground(accent).Bold(true)
		styles.Focused.Description = styles.Focused.Description.Foreground(muted)
		styles.Focused.SelectSelector = styles.Focused.SelectSelector.Foreground(accent)
		styles.Focused.MultiSelectSelector = styles.Focused.MultiSelectSelector.Foreground(accent)
		styles.Focused.SelectedPrefix = styles.Focused.SelectedPrefix.Foreground(success).SetString("✓ ")
		styles.Focused.ErrorIndicator = styles.Focused.ErrorIndicator.Foreground(danger)
		styles.Focused.ErrorMessage = styles.Focused.ErrorMessage.Foreground(danger)
		styles.Blurred = styles.Focused
		styles.Blurred.Base = styles.Blurred.Base.BorderStyle(lipgloss.HiddenBorder())
		styles.Blurred.Title = styles.Blurred.Title.Foreground(muted).Bold(false)
		styles.Group.Title = styles.Focused.Title
		return styles
	})
}

func promptValidator(prompt flow.Prompt) func(string) error {
	return func(value string) error {
		if prompt.Required && strings.TrimSpace(value) == "" {
			return errors.New("a value is required")
		}
		if !utf8.ValidString(value) {
			return errors.New("value must be valid UTF-8")
		}
		if prompt.Validate != nil {
			return prompt.Validate(value)
		}
		return nil
	}
}

func huhOptions(options []flow.Option) []huh.Option[string] {
	result := make([]huh.Option[string], 0, len(options))
	for _, option := range options {
		label := safeText(option.Label)
		if option.Hint != "" {
			label += "  " + safeText(option.Hint)
		}
		if !strings.Contains(strings.ToLower(label), strings.ToLower(option.Value)) {
			label += "  [" + safeText(option.Value) + "]"
		}
		result = append(result, huh.NewOption(label, option.Value))
	}
	return result
}

func (p *Prompter) description(value string, navigation flow.Navigation) string {
	parts := []string{}
	if text := strings.TrimSpace(safeText(value)); text != "" {
		parts = append(parts, text)
	}
	var navigationHelp []string
	if navigation.CanGoBack {
		navigationHelp = append(navigationHelp, "← back")
	}
	if navigation.CanGoForward {
		navigationHelp = append(navigationHelp, "→ forward")
	}
	if len(navigationHelp) > 0 {
		parts = append(parts, strings.Join(navigationHelp, "  "))
	}
	return strings.Join(parts, "\n")
}

func (p *Prompter) line(value string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return errors.New("setup renderer is closed")
	}
	_, err := fmt.Fprintln(p.output, value)
	return err
}

func (p *Prompter) paint(code, value string) string {
	if !p.color {
		return value
	}
	return code + value + ansiReset
}

func colorEnabled(output io.Writer) bool {
	if _, exists := os.LookupEnv("NO_COLOR"); exists && os.Getenv("FORCE_COLOR") == "" {
		return false
	}
	if os.Getenv("FORCE_COLOR") != "" {
		return true
	}
	file, ok := output.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

func terminalWidth(output io.Writer) int {
	file, ok := output.(*os.File)
	if !ok {
		return 80
	}
	width, _, err := term.GetSize(int(file.Fd()))
	if err != nil || width <= 0 {
		return 80
	}
	return width
}

func safeText(value string) string {
	value = strings.ReplaceAll(value, "\x1b", "")
	return controlPattern.ReplaceAllString(value, "")
}

func wrap(value string, width int) []string {
	var result []string
	for _, paragraph := range strings.Split(value, "\n") {
		words := strings.Fields(paragraph)
		if len(words) == 0 {
			result = append(result, "")
			continue
		}
		line := words[0]
		for _, word := range words[1:] {
			if utf8.RuneCountInString(line)+1+utf8.RuneCountInString(word) > width {
				result = append(result, line)
				line = word
			} else {
				line += " " + word
			}
		}
		result = append(result, line)
	}
	return result
}

func selectHeight(count int) int { return min(max(count, 3), 12) }
