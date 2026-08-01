// Package cli provides dependency-free declarative command dispatch, help, and completion.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"
)

const helpWidth = 88

// Handler runs one resolved command with its remaining arguments.
type Handler func(context.Context, []string, io.Writer, io.Writer) error

// FlagSetFactory returns a fresh flag set for parsing or help rendering.
type FlagSetFactory func(io.Writer) *flag.FlagSet

// Command is one node in the public command tree.
type Command struct {
	Name          string
	Summary       string
	Description   string
	Usage         string
	Group         string
	Examples      []string
	Flags         FlagSetFactory
	HiddenFlags   map[string]bool
	RequiredFlags []string
	Children      []*Command
	Hidden        bool
	Run           Handler
}

// App is one complete command-line application.
type App struct {
	Name             string
	Summary          string
	Description      string
	Version          string
	Commands         []*Command
	EnableCompletion bool
}

// UsageError reports invalid command syntax. Main programs should exit with status 2.
type UsageError struct {
	Message     string
	CommandPath string
}

func (err *UsageError) Error() string { return err.Message }

// Usage marks an error as invalid command syntax.
func Usage(err error) error {
	if err == nil {
		return nil
	}
	var usage *UsageError
	if errors.As(err, &usage) {
		return err
	}
	return &UsageError{Message: err.Error()}
}

// Parse parses one command flag set without letting flag print its own usage block.
func Parse(flags *flag.FlagSet, args []string) error {
	flags.Usage = func() {}
	flags.SetOutput(io.Discard)
	if err := flags.Parse(args); err != nil {
		return Usage(err)
	}
	return nil
}

// Run resolves and executes one invocation.
func (app *App) Run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if err := app.Validate(); err != nil {
		return err
	}
	root := app.rootCommand()
	if handled, err := app.runBuiltIn(args, stdout, root); handled {
		return err
	}
	command, rest, err := resolve(root, args)
	if err != nil {
		return err
	}
	return app.runResolved(ctx, root, command, rest, stdout, stderr)
}

func (app *App) runBuiltIn(args []string, stdout io.Writer, root *Command) (bool, error) {
	if len(args) == 0 {
		return true, app.writeHelp(stdout, root, nil)
	}
	if len(args) == 1 && (args[0] == "--version" || args[0] == "-v") {
		_, err := fmt.Fprintln(stdout, app.Version)
		return true, err
	}
	if args[0] != "help" {
		return false, nil
	}
	return true, app.runHelp(args[1:], stdout, root)
}

func (app *App) runHelp(args []string, stdout io.Writer, root *Command) error {
	command, rest, err := resolve(root, args)
	if err != nil {
		return err
	}
	if len(rest) != 0 && !hasHelpFlag(rest) {
		return app.usageError(command, fmt.Sprintf("help does not accept %q", rest[0]))
	}
	return app.writeHelp(stdout, command, commandPath(root, command))
}

func (app *App) runResolved(ctx context.Context, root, command *Command, args []string, stdout, stderr io.Writer) error {
	path := commandPath(root, command)
	if hasHelpFlag(args) {
		return app.writeHelp(stdout, command, path)
	}
	if command.Run == nil {
		return app.runGroup(stdout, command, path, args)
	}
	if err := command.Run(ctx, args, stdout, stderr); err != nil {
		setUsageCommandPath(err, path)
		return err
	}
	return nil
}

func (app *App) runGroup(stdout io.Writer, command *Command, path, args []string) error {
	if len(args) == 0 {
		return app.writeHelp(stdout, command, path)
	}
	err := unknownCommandError(command, args[0])
	err.CommandPath = strings.Join(path, " ")
	return err
}

func setUsageCommandPath(err error, path []string) {
	var usage *UsageError
	if errors.As(err, &usage) && usage.CommandPath == "" {
		usage.CommandPath = strings.Join(path, " ")
	}
}

// Validate checks that help, dispatch, and completion metadata agree.
func (app *App) Validate() error {
	if !validCommandName(app.Name) || strings.TrimSpace(app.Summary) == "" {
		return errors.New("CLI application name and summary are required")
	}
	return validateCommands(app.rootCommand(), app.Name)
}

func validateCommands(parent *Command, path string) error {
	seen := map[string]bool{}
	for _, command := range parent.Children {
		commandPath := path + " " + command.Name
		if seen[command.Name] {
			return fmt.Errorf("CLI command %q has an invalid or duplicate name", commandPath)
		}
		seen[command.Name] = true
		if err := validateCommand(command, commandPath); err != nil {
			return err
		}
		if err := validateCommands(command, commandPath); err != nil {
			return err
		}
	}
	return nil
}

func validateCommand(command *Command, path string) error {
	if !validCommandName(command.Name) && !hiddenInternalName(command) {
		return fmt.Errorf("CLI command %q has an invalid or duplicate name", path)
	}
	if missingCommandSummary(command) {
		return fmt.Errorf("CLI command %q has no summary", path)
	}
	if missingCommandHandler(command) {
		return fmt.Errorf("CLI command %q has no handler", path)
	}
	if missingCommandDescription(command) {
		return fmt.Errorf("CLI command %q has no description", path)
	}
	return validateCommandFlags(command, path)
}

func hiddenInternalName(command *Command) bool {
	return command.Hidden && strings.HasPrefix(command.Name, "__")
}

func missingCommandSummary(command *Command) bool {
	return !command.Hidden && strings.TrimSpace(command.Summary) == ""
}

func missingCommandHandler(command *Command) bool {
	return len(command.Children) == 0 && command.Run == nil
}

func missingCommandDescription(command *Command) bool {
	return len(command.Children) == 0 && !command.Hidden && strings.TrimSpace(command.Description) == ""
}

func validateCommandFlags(command *Command, path string) error {
	if len(command.RequiredFlags) == 0 && len(command.HiddenFlags) == 0 {
		return nil
	}
	if command.Flags == nil {
		return fmt.Errorf("CLI command %q describes flags without a flag set", path)
	}
	flags := command.Flags(io.Discard)
	if err := validateRequiredFlags(flags, command.RequiredFlags, path); err != nil {
		return err
	}
	return validateHiddenFlags(flags, command.HiddenFlags, path)
}

func validateRequiredFlags(flags *flag.FlagSet, names []string, path string) error {
	for _, name := range names {
		if flags.Lookup(name) == nil {
			return fmt.Errorf("CLI command %q requires unknown flag %q", path, name)
		}
	}
	return nil
}

func validateHiddenFlags(flags *flag.FlagSet, names map[string]bool, path string) error {
	for name := range names {
		if flags.Lookup(name) == nil {
			return fmt.Errorf("CLI command %q hides unknown flag %q", path, name)
		}
	}
	return nil
}

func validCommandName(value string) bool {
	if value == "" || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if !validCommandCharacter(character) {
			return false
		}
	}
	return true
}

func validCommandCharacter(character rune) bool {
	if character == '-' || character == '_' {
		return true
	}
	if character >= 'a' && character <= 'z' {
		return true
	}
	return character >= '0' && character <= '9'
}

func (app *App) rootCommand() *Command {
	children := append([]*Command(nil), app.Commands...)
	if app.EnableCompletion {
		children = append(children, app.completionCommand(), app.dynamicCompletionCommand())
	}
	return &Command{Name: app.Name, Summary: app.Summary, Description: app.Description, Children: children}
}

func resolve(root *Command, args []string) (*Command, []string, error) {
	current := root
	path := []string{root.Name}
	for len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		child := childNamed(current, args[0])
		if child == nil {
			if current.Run != nil {
				break
			}
			err := unknownCommandError(current, args[0])
			err.CommandPath = strings.Join(path, " ")
			return nil, nil, err
		}
		current = child
		path = append(path, child.Name)
		args = args[1:]
	}
	return current, args, nil
}

func childNamed(command *Command, name string) *Command {
	for _, child := range command.Children {
		if child.Name == name {
			return child
		}
	}
	return nil
}

func hasHelpFlag(args []string) bool {
	return slices.Contains(args, "--help") || slices.Contains(args, "-h")
}

func unknownCommandError(command *Command, name string) *UsageError {
	message := fmt.Sprintf("unknown command %q", name)
	if suggestion := closestCommand(command, name); suggestion != "" {
		message += fmt.Sprintf("; did you mean %q?", suggestion)
	}
	return &UsageError{Message: message}
}

func (app *App) usageError(command *Command, message string) error {
	return &UsageError{Message: message, CommandPath: strings.Join(commandPath(app.rootCommand(), command), " ")}
}

func closestCommand(command *Command, value string) string {
	best, distance := "", len(value)+1
	for _, child := range command.Children {
		if child.Hidden {
			continue
		}
		candidate := levenshtein(value, child.Name)
		if candidate < distance || candidate == distance && child.Name < best {
			best, distance = child.Name, candidate
		}
	}
	limit := 2
	if len(value) >= 9 {
		limit = 3
	}
	if distance > limit {
		return ""
	}
	return best
}

func levenshtein(left, right string) int {
	a, b := []rune(left), []rune(right)
	previous := make([]int, len(b)+1)
	for index := range previous {
		previous[index] = index
	}
	for i, ar := range a {
		current := make([]int, len(b)+1)
		current[0] = i + 1
		for j, br := range b {
			cost := 0
			if ar != br {
				cost = 1
			}
			current[j+1] = min(current[j]+1, previous[j+1]+1, previous[j]+cost)
		}
		previous = current
	}
	return previous[len(b)]
}

func commandPath(root, target *Command) []string {
	if root == target {
		return []string{root.Name}
	}
	var visit func(*Command, []string) []string
	visit = func(command *Command, path []string) []string {
		if command == target {
			return path
		}
		for _, child := range command.Children {
			if result := visit(child, append(path, child.Name)); result != nil {
				return result
			}
		}
		return nil
	}
	return visit(root, []string{root.Name})
}

func (app *App) writeHelp(writer io.Writer, command *Command, path []string) error {
	if path == nil {
		path = []string{app.Name}
	}
	steps := []func() error{
		func() error { return app.writeHelpIntroduction(writer, command, len(path) == 1) },
		func() error { return writeHelpUsage(writer, command, path) },
		func() error { return writeCommandGroups(writer, command) },
		func() error { return writeOptions(writer, command, len(path) == 1) },
		func() error { return writeExamples(writer, command.Examples) },
		func() error { return app.writeHelpFooter(writer, command, path) },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

func (app *App) writeHelpIntroduction(writer io.Writer, command *Command, root bool) error {
	heading, description := command.Summary, command.Description
	if root {
		heading, description = app.Summary, app.Description
	}
	if heading != "" {
		if _, err := fmt.Fprintln(writer, heading); err != nil {
			return err
		}
	}
	if description != "" {
		_, err := fmt.Fprintf(writer, "\n%s\n", wrap(description, helpWidth))
		return err
	}
	return nil
}

func writeHelpUsage(writer io.Writer, command *Command, path []string) error {
	usage := command.Usage
	if usage == "" {
		usage = inferredUsage(command)
	}
	line := strings.Join(path, " ")
	if usage != "" {
		line += " " + usage
	}
	_, err := fmt.Fprintf(writer, "\nUsage:\n  %s\n", line)
	return err
}

func inferredUsage(command *Command) string {
	if len(visibleChildren(command)) > 0 {
		if command.Run != nil {
			return "[command] [flags]"
		}
		return "<command>"
	}
	if command.Flags != nil {
		return "[flags]"
	}
	return ""
}

func writeExamples(writer io.Writer, examples []string) error {
	if len(examples) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(writer, "\nExamples:"); err != nil {
		return err
	}
	for _, example := range examples {
		if _, err := fmt.Fprintf(writer, "  %s\n", example); err != nil {
			return err
		}
	}
	return nil
}

func (app *App) writeHelpFooter(writer io.Writer, command *Command, path []string) error {
	if len(visibleChildren(command)) == 0 {
		return nil
	}
	helpPath := append([]string{app.Name, "help"}, path[1:]...)
	helpPath = append(helpPath, "<command>")
	_, err := fmt.Fprintf(writer, "\nRun %q for more information.\n", strings.Join(helpPath, " "))
	return err
}

func visibleChildren(command *Command) []*Command {
	var result []*Command
	for _, child := range command.Children {
		if !child.Hidden {
			result = append(result, child)
		}
	}
	return result
}

func writeCommandGroups(writer io.Writer, command *Command) error {
	groups, order := commandGroups(command)
	for _, group := range order {
		if err := writeCommandGroup(writer, group, groups[group]); err != nil {
			return err
		}
	}
	return nil
}

func commandGroups(command *Command) (map[string][]*Command, []string) {
	groups := map[string][]*Command{}
	var order []string
	for _, child := range visibleChildren(command) {
		group := child.Group
		if group == "" {
			group = "Commands"
		}
		if _, exists := groups[group]; !exists {
			order = append(order, group)
		}
		groups[group] = append(groups[group], child)
	}
	return groups, order
}

func writeCommandGroup(writer io.Writer, name string, children []*Command) error {
	sort.Slice(children, func(i, j int) bool { return children[i].Name < children[j].Name })
	width := 0
	for _, child := range children {
		width = max(width, utf8.RuneCountInString(child.Name))
	}
	if _, err := fmt.Fprintf(writer, "\n%s:\n", name); err != nil {
		return err
	}
	for _, child := range children {
		if _, err := fmt.Fprintf(writer, "  %-*s  %s\n", width, child.Name, child.Summary); err != nil {
			return err
		}
	}
	return nil
}

type helpOption struct{ label, description string }

func writeOptions(writer io.Writer, command *Command, root bool) error {
	options := collectHelpOptions(command, root)
	width := 0
	for _, option := range options {
		width = max(width, utf8.RuneCountInString(option.label))
	}
	if _, err := fmt.Fprintln(writer, "\nOptions:"); err != nil {
		return err
	}
	for _, option := range options {
		if _, err := fmt.Fprintf(writer, "  %-*s  %s\n", width, option.label, option.description); err != nil {
			return err
		}
	}
	return nil
}

func collectHelpOptions(command *Command, root bool) []helpOption {
	options := []helpOption{{"-h, --help", "show help"}}
	if root {
		options = append(options, helpOption{"-v, --version", "print the installed version"})
	}
	if command.Flags == nil {
		return options
	}
	required := make(map[string]bool, len(command.RequiredFlags))
	for _, name := range command.RequiredFlags {
		required[name] = true
	}
	flags := command.Flags(io.Discard)
	flags.VisitAll(func(value *flag.Flag) {
		if !command.HiddenFlags[value.Name] {
			options = append(options, describeHelpOption(value, required[value.Name]))
		}
	})
	return options
}

func describeHelpOption(value *flag.Flag, required bool) helpOption {
	metavar, description := flag.UnquoteUsage(value)
	label := "--" + value.Name
	if !isBooleanFlag(value) {
		if metavar == "" {
			metavar = "VALUE"
		}
		label += " " + metavar
	}
	if required {
		description += " (required)"
	} else if value.DefValue != "" && value.DefValue != "false" && value.DefValue != "0" {
		description += " (default: " + value.DefValue + ")"
	}
	return helpOption{label, description}
}

func isBooleanFlag(value *flag.Flag) bool {
	boolean, ok := value.Value.(interface{ IsBoolFlag() bool })
	return ok && boolean.IsBoolFlag()
}

func wrap(value string, width int) string {
	words := strings.Fields(value)
	if len(words) == 0 {
		return ""
	}
	var lines []string
	line := words[0]
	for _, word := range words[1:] {
		if utf8.RuneCountInString(line)+1+utf8.RuneCountInString(word) <= width {
			line += " " + word
			continue
		}
		lines = append(lines, line)
		line = word
	}
	return strings.Join(append(lines, line), "\n")
}
