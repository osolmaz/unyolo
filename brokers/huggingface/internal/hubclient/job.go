package hubclient

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const maxJobsPerPage = 100

var validJobStages = map[string]struct{}{
	"CANCELED": {}, "COMPLETED": {}, "DELETED": {}, "ERROR": {}, "RUNNING": {}, "SCHEDULING": {},
}

// JobListOptions contains the bounded filters accepted by the Hub Jobs list
// route. Cursor values are opaque and may only come from a prior JobPage.
type JobListOptions struct {
	Stages []string
	Labels map[string]string
	Cursor string
}

// JobSummary is the deliberately small, secret-free projection returned by
// Jobs reads. It excludes commands, arguments, environment values, secret
// names, token metadata, URLs, and other execution details.
type JobSummary struct {
	ID         string `json:"id"`
	Owner      string `json:"owner"`
	Stage      string `json:"stage"`
	CreatedAt  string `json:"created_at"`
	StartedAt  string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
	Flavor     string `json:"flavor"`
}

// JobPage is one bounded upstream page plus its opaque continuation cursor.
type JobPage struct {
	Jobs       []JobSummary
	NextCursor string
}

type jobResponse struct {
	ID         string `json:"id"`
	CreatedAt  string `json:"createdAt"`
	StartedAt  string `json:"startedAt"`
	FinishedAt string `json:"finishedAt"`
	Flavor     string `json:"flavor"`
	Owner      struct {
		Name string `json:"name"`
	} `json:"owner"`
	Status struct {
		Stage string `json:"stage"`
	} `json:"status"`
}

// ListJobs reads one bounded Hub Jobs page for an exact namespace.
func (c *Client) ListJobs(ctx context.Context, namespace string, options JobListOptions) (JobPage, error) {
	if !ValidNamespaceSegment(namespace) || !ValidJobListOptions(options) {
		return JobPage{}, errors.New("hubclient: job list input is invalid")
	}
	var response []jobResponse
	var header http.Header
	path := "/api/jobs/" + url.PathEscape(namespace)
	if err := c.call(ctx, callSpec{method: http.MethodGet, path: path, query: jobListQuery(options), out: &response, captureHeader: &header}); err != nil {
		return JobPage{}, err
	}
	jobs, ok := projectJobPage(response, namespace)
	if !ok {
		return JobPage{}, &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
	}
	next, ok := nextJobCursor(header.Values("Link"), c.base, path)
	if !ok {
		return JobPage{}, &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
	}
	return JobPage{Jobs: jobs, NextCursor: next}, nil
}

func jobListQuery(options JobListOptions) url.Values {
	query := make(url.Values)
	stages := slices.Clone(options.Stages)
	slices.Sort(stages)
	for _, stage := range stages {
		query.Add("stage", stage)
	}
	labelNames := make([]string, 0, len(options.Labels))
	for name := range options.Labels {
		labelNames = append(labelNames, name)
	}
	slices.Sort(labelNames)
	for _, name := range labelNames {
		query.Add("label", name+"="+options.Labels[name])
	}
	if options.Cursor != "" {
		query.Set("cursor", options.Cursor)
	}
	return query
}

func projectJobPage(response []jobResponse, namespace string) ([]JobSummary, bool) {
	if len(response) > maxJobsPerPage {
		return nil, false
	}
	jobs := make([]JobSummary, len(response))
	for index, raw := range response {
		projected, ok := projectJob(raw, namespace, "")
		if !ok {
			return nil, false
		}
		jobs[index] = projected
	}
	return jobs, true
}

// ReadJob reads one exact Hub Job and returns only its safe summary.
func (c *Client) ReadJob(ctx context.Context, namespace, jobID string) (JobSummary, error) {
	if !ValidNamespaceSegment(namespace) || !ValidJobID(jobID) {
		return JobSummary{}, errors.New("hubclient: job reference is invalid")
	}
	var response jobResponse
	path := "/api/jobs/" + url.PathEscape(namespace) + "/" + url.PathEscape(jobID)
	if err := c.call(ctx, callSpec{method: http.MethodGet, path: path, out: &response}); err != nil {
		return JobSummary{}, err
	}
	projected, ok := projectJob(response, namespace, jobID)
	if !ok {
		return JobSummary{}, &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
	}
	return projected, nil
}

// ValidJobID reports whether a value can be embedded in the fixed Jobs route.
func ValidJobID(value string) bool { return sandboxIDPattern.MatchString(value) }

// ValidJobListOptions reports whether filters fit the fixed Jobs list route.
func ValidJobListOptions(options JobListOptions) bool {
	return len(options.Stages) <= len(validJobStages) && len(options.Labels) <= 16 && validJobCursor(options.Cursor) &&
		validJobStageFilters(options.Stages) && validJobLabels(options.Labels)
}

func validJobCursor(value string) bool {
	return len(value) <= 2048 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func validJobStageFilters(stages []string) bool {
	seen := make(map[string]struct{}, len(stages))
	for _, stage := range stages {
		if _, ok := validJobStages[stage]; !ok {
			return false
		}
		if _, duplicate := seen[stage]; duplicate {
			return false
		}
		seen[stage] = struct{}{}
	}
	return true
}

func validJobLabels(labels map[string]string) bool {
	for name, value := range labels {
		if !validJobLabelPart(name) || !validJobLabelPart(value) {
			return false
		}
	}
	return true
}

func validJobLabelPart(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n=")
}

func projectJob(value jobResponse, namespace, expectedID string) (JobSummary, bool) {
	if !validJobResponseIdentity(value, namespace, expectedID) || !validJobResponseFields(value) {
		return JobSummary{}, false
	}
	return JobSummary{ID: value.ID, Owner: value.Owner.Name, Stage: value.Status.Stage, CreatedAt: value.CreatedAt,
		StartedAt: value.StartedAt, FinishedAt: value.FinishedAt, Flavor: value.Flavor}, true
}

func validJobResponseIdentity(value jobResponse, namespace, expectedID string) bool {
	return ValidJobID(value.ID) && (expectedID == "" || value.ID == expectedID) && value.Owner.Name == namespace
}

func validJobResponseFields(value jobResponse) bool {
	return len(value.Flavor) > 0 && len(value.Flavor) <= 64 && validBoundedJobStage(value.Status.Stage) &&
		validJobTime(value.CreatedAt, true) && validJobTime(value.StartedAt, false) && validJobTime(value.FinishedAt, false)
}

func validBoundedJobStage(value string) bool {
	return value != "" && len(value) <= 64 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func validJobTime(value string, required bool) bool {
	if value == "" {
		return !required
	}
	_, err := time.Parse(time.RFC3339Nano, value)
	return err == nil
}

func nextJobCursor(headers []string, base, expectedPath string) (string, bool) {
	for _, header := range headers {
		for _, part := range strings.Split(header, ",") {
			cursor, next, valid := parseJobNextLink(strings.TrimSpace(part), base, expectedPath)
			if !valid {
				return "", false
			}
			if next {
				return cursor, true
			}
		}
	}
	return "", true
}

func parseJobNextLink(part, base, expectedPath string) (string, bool, bool) {
	if !strings.Contains(part, `rel="next"`) {
		return "", false, true
	}
	next, ok := parseJobPageURL(part, base, expectedPath)
	if !ok {
		return "", true, false
	}
	cursor := next.Query().Get("cursor")
	return cursor, true, cursor != "" && validJobCursor(cursor)
}

func parseJobPageURL(part, base, expectedPath string) (*url.URL, bool) {
	if !strings.HasPrefix(part, "<") {
		return nil, false
	}
	end := strings.IndexByte(part, '>')
	if end < 2 {
		return nil, false
	}
	next, err := url.Parse(part[1:end])
	origin, originErr := url.Parse(base)
	return next, err == nil && originErr == nil && sameJobPageOrigin(next, origin, expectedPath)
}

func sameJobPageOrigin(next, origin *url.URL, expectedPath string) bool {
	return next.Scheme == origin.Scheme && next.Host == origin.Host && next.Path == expectedPath && next.User == nil && next.Fragment == ""
}
