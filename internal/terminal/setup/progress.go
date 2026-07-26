package setup

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/term"
)

var spinnerFrames = []string{"◐", "◓", "◑", "◒"}

type indicator struct {
	prompter *Prompter
	mu       sync.Mutex
	label    string
	done     chan struct{}
	stopped  bool
	animated bool
}

func newIndicator(prompter *Prompter, label string) *indicator {
	file, ok := prompter.output.(*os.File)
	animated := ok && term.IsTerminal(int(file.Fd())) && !prompter.accessible
	return &indicator{prompter: prompter, label: safeText(label), done: make(chan struct{}), animated: animated}
}

func (item *indicator) start() {
	if !item.animated {
		_ = item.prompter.line("│  … " + item.renderLabel())
		return
	}
	go item.animate()
}

func (item *indicator) animate() {
	ticker := time.NewTicker(120 * time.Millisecond)
	defer ticker.Stop()
	frame := 0
	for {
		select {
		case <-item.done:
			return
		case <-ticker.C:
			item.mu.Lock()
			if item.stopped {
				item.mu.Unlock()
				return
			}
			label := item.renderLabelLocked()
			item.mu.Unlock()
			item.prompter.mu.Lock()
			_, _ = fmt.Fprintf(item.prompter.output, "\r\x1b[2K%s│  %s %s%s", ansiAccent, spinnerFrames[frame%len(spinnerFrames)], label, ansiReset)
			item.prompter.mu.Unlock()
			frame++
		}
	}
}

func (item *indicator) Update(message string) {
	item.mu.Lock()
	if !item.stopped {
		item.label = safeText(message)
	}
	item.mu.Unlock()
}

func (item *indicator) Stop(message string) { item.stop(message, false) }
func (item *indicator) Fail(message string) { item.stop(message, true) }

func (item *indicator) stop(message string, failed bool) {
	item.mu.Lock()
	if item.stopped {
		item.mu.Unlock()
		return
	}
	item.stopped = true
	close(item.done)
	if message == "" {
		message = item.label
	}
	message = item.renderText(message)
	item.mu.Unlock()

	item.prompter.mu.Lock()
	delete(item.prompter.progress, item)
	prefix, color := "✓", ansiGreen
	if failed {
		prefix, color = "✗", ansiRed
	}
	if item.animated {
		_, _ = fmt.Fprint(item.prompter.output, "\r\x1b[2K")
	}
	line := "│  " + prefix + " " + message
	if item.prompter.color {
		line = color + line + ansiReset
	}
	_, _ = fmt.Fprintln(item.prompter.output, line)
	item.prompter.mu.Unlock()
}

func (item *indicator) renderLabel() string {
	item.mu.Lock()
	defer item.mu.Unlock()
	return item.renderLabelLocked()
}

func (item *indicator) renderLabelLocked() string { return item.renderText(item.label) }

func (item *indicator) renderText(value string) string {
	width := item.prompter.width
	if file, ok := item.prompter.output.(*os.File); ok {
		if current, _, err := term.GetSize(int(file.Fd())); err == nil && current > 0 {
			width = min(width, current)
		}
	}
	limit := max(0, width-8)
	if utf8.RuneCountInString(value) <= limit {
		return value
	}
	if limit <= 1 {
		return ""
	}
	runes := []rune(strings.TrimSpace(value))
	return string(runes[:min(len(runes), limit-1)]) + "…"
}
