package upstreamdrift

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

const maxReportedChanges = 200

// WriteMarkdown writes an issue-ready report with bounded detail.
func WriteMarkdown(writer io.Writer, report Report) error {
	if writer == nil {
		return fmt.Errorf("report writer is nil")
	}
	status := "No structural drift detected"
	if report.HasDrift() {
		status = "Structural drift detected"
	}
	if _, err := fmt.Fprintf(writer, "# GitHub capability drift\n\n**%s.**\n\nRetrieved: `%s`\n\n", status, report.RetrievedAt.UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	if err := writeSources(writer, report.Sources); err != nil {
		return err
	}
	if err := writeSummary(writer, report.Changes); err != nil {
		return err
	}
	return writeDetails(writer, report.Changes)
}

func writeSources(writer io.Writer, sources []Source) error {
	if _, err := io.WriteString(writer, "## Verified sources\n\n| Kind | API version | Commit | SHA-256 |\n| --- | --- | --- | --- |\n"); err != nil {
		return err
	}
	ordered := slices.Clone(sources)
	slices.SortFunc(ordered, func(left, right Source) int { return strings.Compare(left.Kind, right.Kind) })
	for _, source := range ordered {
		commit := source.Commit
		if commit == "" {
			commit = "live endpoint"
		}
		if _, err := fmt.Fprintf(writer, "| %s | %s | `%s` | `%s` |\n", safeCell(source.Kind), safeCell(source.APIVersion), safeCell(commit), safeCell(source.SHA256)); err != nil {
			return err
		}
	}
	_, err := io.WriteString(writer, "\nEvery repository input was resolved to an immutable commit before download. The GraphQL schema is identified by its response digest.\n\n")
	return err
}

func writeSummary(writer io.Writer, changes []Change) error {
	counts := map[string]int{}
	for _, change := range changes {
		counts[change.Category]++
	}
	if _, err := io.WriteString(writer, "## Summary\n\n| Category | Changes |\n| --- | ---: |\n"); err != nil {
		return err
	}
	for _, category := range []string{CategoryAPIVersion, CategoryOperation, CategorySchema, CategoryPermission, CategoryAuthentication, CategoryDeprecation} {
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
		if _, err := fmt.Fprintf(writer, "- `%s` %s `%s`\n", safeCell(change.Category), safeCell(change.Kind), safeInline(change.Key)); err != nil {
			return err
		}
	}
	if omitted := len(changes) - limit; omitted > 0 {
		if _, err := fmt.Fprintf(writer, "- %d additional changes omitted from this bounded report.\n", omitted); err != nil {
			return err
		}
	}
	_, err := io.WriteString(writer, "\nReview the official changes, refresh all pinned inputs in one pull request, regenerate every GitHub catalog artifact, and run the complete conformance suite. This monitor never refreshes or merges snapshots.\n")
	return err
}

func safeCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}

func safeInline(value string) string { return strings.ReplaceAll(value, "`", "'") }

func latestRetrieval(sources []Source) time.Time {
	var result time.Time
	for _, source := range sources {
		if source.RetrievedAt.After(result) {
			result = source.RetrievedAt
		}
	}
	return result
}
