package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
)

func (app *App) completionCommand() *Command {
	command := &Command{
		Name:        "completion",
		Summary:     "Generate shell completion",
		Description: "Print a completion script for the selected shell.",
		Usage:       "<bash|zsh|fish>",
		Group:       "Utilities",
	}
	for _, shell := range []string{"bash", "zsh", "fish"} {
		shell := shell
		command.Children = append(command.Children, &Command{
			Name:        shell,
			Summary:     "Generate completion for " + shell,
			Description: "Print the unYOLO completion script for " + shell + ".",
			Examples:    completionExamples(shell),
			Run: func(_ context.Context, args []string, stdout, _ io.Writer) error {
				if len(args) != 0 {
					return Usage(fmt.Errorf("completion %s does not accept positional arguments", shell))
				}
				_, err := io.WriteString(stdout, completionScript(shell, app.Name))
				return err
			},
		})
	}
	return command
}

func completionExamples(shell string) []string {
	switch shell {
	case "bash":
		return []string{"source <(unyolo completion bash)"}
	case "zsh":
		return []string{"source <(unyolo completion zsh)"}
	default:
		return []string{"unyolo completion fish | source"}
	}
}

const emptyCompletionWord = "__unyolo_empty_completion_word__"

func (app *App) dynamicCompletionCommand() *Command {
	return &Command{
		Name:   "__complete",
		Hidden: true,
		Run: func(_ context.Context, args []string, stdout, _ io.Writer) error {
			for _, candidate := range app.completionCandidates(normalizeCompletionWords(args)) {
				if _, err := fmt.Fprintln(stdout, candidate); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func normalizeCompletionWords(words []string) []string {
	if len(words) == 0 || words[len(words)-1] != emptyCompletionWord {
		return words
	}
	result := append([]string(nil), words...)
	result[len(result)-1] = ""
	return result
}

func (app *App) completionCandidates(words []string) []string {
	root := app.rootCommand()
	current, prefix := completionContext(root, words)
	result := completionFlagNames(root, current, prefix)
	result = append(result, completionCommandNames(current, prefix)...)
	sort.Strings(result)
	return result
}

func completionContext(root *Command, words []string) (*Command, string) {
	current, prefix := root, ""
	if len(words) == 0 {
		return current, prefix
	}
	prefix = words[len(words)-1]
	for _, word := range words[:len(words)-1] {
		if strings.HasPrefix(word, "-") {
			continue
		}
		if child := childNamed(current, word); child != nil {
			current = child
		}
	}
	return current, prefix
}

func completionFlagNames(root, current *Command, prefix string) []string {
	flagsRequested := strings.HasPrefix(prefix, "-") || prefix == "" && len(visibleChildren(current)) == 0
	if !flagsRequested {
		return nil
	}
	result := commandFlagNames(current, prefix)
	if current == root && strings.HasPrefix("--version", prefix) {
		result = append(result, "--version")
	}
	return result
}

func completionCommandNames(current *Command, prefix string) []string {
	if strings.HasPrefix(prefix, "-") {
		return nil
	}
	var result []string
	for _, child := range visibleChildren(current) {
		if strings.HasPrefix(child.Name, prefix) {
			result = append(result, child.Name)
		}
	}
	return result
}

func commandFlagNames(command *Command, prefix string) []string {
	result := []string{"--help"}
	if command.Flags != nil {
		flags := command.Flags(io.Discard)
		flags.VisitAll(func(value *flag.Flag) {
			if command.HiddenFlags[value.Name] {
				return
			}
			name := "--" + value.Name
			if strings.HasPrefix(name, prefix) {
				result = append(result, name)
			}
		})
	}
	return slices.DeleteFunc(result, func(value string) bool { return !strings.HasPrefix(value, prefix) })
}

func completionScript(shell, name string) string {
	switch shell {
	case "bash":
		return fmt.Sprintf(`# bash completion for %[1]s
_%[1]s_complete() {
  local IFS=$'\n'
  COMPREPLY=($(command %[1]s __complete "${COMP_WORDS[@]:1}"))
}
complete -F _%[1]s_complete %[1]s
`, name)
	case "zsh":
		return fmt.Sprintf(`#compdef %[1]s
_%[1]s() {
  local -a suggestions
  suggestions=("${(@f)$(command %[1]s __complete "${words[@]:2}")}")
  compadd -- $suggestions
}
compdef _%[1]s %[1]s
`, name)
	default:
		return fmt.Sprintf(`function __%[1]s_complete
  set -l tokens (commandline -opc)
  set -e tokens[1]
  set -l current (commandline -ct)
  if string match -q -- '* ' (commandline)
    set current %[2]s
  end
  command %[1]s __complete $tokens $current
end
complete -c %[1]s -f -a '(__%[1]s_complete)'
`, name, emptyCompletionWord)
	}
}
