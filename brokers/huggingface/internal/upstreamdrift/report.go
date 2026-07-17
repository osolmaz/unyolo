package upstreamdrift

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const maxReportedChanges = 200

// WriteMarkdown writes an issue-ready, bounded maintenance report.
func WriteMarkdown(writer io.Writer, report Report) error {
	if writer == nil {
		return errors.New("report writer is nil")
	}
	status := "No structural drift detected"
	if report.HasDrift() {
		status = "Structural drift detected"
	}
	if _, err := fmt.Fprintf(
		writer,
		"# Hugging Face capability drift\n\n**%s.**\n\nRetrieved: `%s`\n\nSource: [%s](%s)\n\nSHA-256: `%s`\n\n",
		status,
		report.Source.RetrievedAt.UTC().Format(time.RFC3339),
		report.Source.URL,
		report.Source.URL,
		report.Source.SHA256,
	); err != nil {
		return err
	}
	if err := writeSummary(writer, report.Changes); err != nil {
		return err
	}
	return writeDetails(writer, report.Changes)
}

func writeSummary(writer io.Writer, changes []Change) error {
	counts := map[string]int{}
	for _, change := range changes {
		counts[change.Category]++
	}
	if _, err := io.WriteString(writer, "## Summary\n\n| Category | Changes |\n| --- | ---: |\n"); err != nil {
		return err
	}
	for _, category := range []string{"operation", "schema", "authentication", "deprecation"} {
		if _, err := fmt.Fprintf(writer, "| %s | %d |\n", category, counts[category]); err != nil {
			return err
		}
	}
	_, err := io.WriteString(writer, "\n")
	return err
}

func writeDetails(writer io.Writer, changes []Change) error {
	if len(changes) == 0 {
		_, err := io.WriteString(writer, "No snapshot refresh is required.\n")
		return err
	}
	if _, err := io.WriteString(writer, "## Changes\n\n"); err != nil {
		return err
	}
	limit := min(len(changes), maxReportedChanges)
	for _, change := range changes[:limit] {
		if _, err := fmt.Fprintf(writer, "- `%s` %s `%s`\n", safeInline(change.Category), safeInline(change.Kind), safeInline(change.Key)); err != nil {
			return err
		}
	}
	if omitted := len(changes) - limit; omitted > 0 {
		if _, err := fmt.Fprintf(writer, "- %d additional changes omitted from this bounded report.\n", omitted); err != nil {
			return err
		}
	}
	_, err := io.WriteString(writer, "\nReview the official changes, update the pinned snapshot and operation inventory in one pull request, regenerate affected capability artifacts, and run the complete conformance suite. This monitor never refreshes or merges snapshots.\n")
	return err
}

func safeInline(value string) string {
	return strings.NewReplacer("`", "'", "\n", " ").Replace(value)
}
