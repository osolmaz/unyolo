package operations

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/brokers/huggingface/internal/hubclient"
	hfpolicy "github.com/osolmaz/unyolo/brokers/huggingface/internal/policy"
)

type jobReadFake struct {
	page      hubclient.JobPage
	job       hubclient.JobSummary
	namespace string
	jobID     string
	options   hubclient.JobListOptions
}

func (f *jobReadFake) ListJobs(_ context.Context, namespace string, options hubclient.JobListOptions) (hubclient.JobPage, error) {
	f.namespace, f.options = namespace, options
	return f.page, nil
}

func (f *jobReadFake) ReadJob(_ context.Context, namespace, jobID string) (hubclient.JobSummary, error) {
	f.namespace, f.jobID = namespace, jobID
	return f.job, nil
}

func TestJobReadAdaptersExposeOnlySafeBoundedResults(t *testing.T) {
	observed := time.Date(2026, 8, 7, 12, 30, 0, 0, time.UTC)
	fake := &jobReadFake{page: hubclient.JobPage{
		Jobs:       []hubclient.JobSummary{{ID: "job_1", Owner: "acme", Stage: "RUNNING", CreatedAt: "2026-08-07T12:00:00Z", Flavor: "cpu-basic"}},
		NextCursor: "next",
	}, job: hubclient.JobSummary{ID: "job_1", Owner: "acme", Stage: "ERROR", CreatedAt: "2026-08-07T12:00:00Z", FinishedAt: "2026-08-07T12:10:00Z", Flavor: "cpu-basic"}}
	adapters, err := NewJobReadAdapters(fake, func() time.Time { return observed })
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := NewRegistry(adapters...)
	list, _ := registry.Lookup("job.list")
	input, err := list.Decode(json.RawMessage(`{"kind":"job","owner":"acme","name":"*"}`),
		json.RawMessage(`{"stages":["RUNNING"],"labels":{"team":"infra"},"cursor":"prior"}`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := list.Resolve(context.Background(), input)
	if err != nil || hfpolicy.ValidateRequest(list.Authorize(plan)) != nil {
		t.Fatalf("Resolve()/Authorize() = %#v, %v", plan, err)
	}
	outcome, err := list.Execute(context.Background(), plan)
	if err != nil || !outcome.Proven {
		t.Fatalf("Execute() = %#v, %v", outcome, err)
	}
	var result map[string]any
	if err := json.Unmarshal(outcome.Result, &result); err != nil {
		t.Fatal(err)
	}
	jobs, _ := result["jobs"].([]any)
	job, _ := jobs[0].(map[string]any)
	identity, _ := job["identity"].(map[string]any)
	if result["next_cursor"] != "next" || job["state"] != "running" || job["observed_at"] != "2026-08-07T12:30:00Z" ||
		identity["provider"] != "huggingface" || identity["job_id"] != "job_1" {
		t.Fatalf("safe list result = %s", outcome.Result)
	}
	for _, forbidden := range []string{"environment", "command", "arguments", "secrets", "hf_token", "token", "url"} {
		if _, found := job[forbidden]; found {
			t.Fatalf("forbidden result field %q = %s", forbidden, outcome.Result)
		}
	}
	if fake.namespace != "acme" || fake.options.Cursor != "prior" || len(fake.options.Stages) != 1 {
		t.Fatalf("list call = namespace %q, options %#v", fake.namespace, fake.options)
	}

	read, _ := registry.Lookup("job.read")
	input, err = read.Decode(json.RawMessage(`{"kind":"job","owner":"acme","name":"job_1"}`), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	plan, _ = read.Resolve(context.Background(), input)
	outcome, err = read.Execute(context.Background(), plan)
	if err != nil || fake.jobID != "job_1" {
		t.Fatalf("job.read = %s, %v", outcome.Result, err)
	}
	if err := json.Unmarshal(outcome.Result, &job); err != nil || job["state"] != "failed" {
		t.Fatalf("read result = %s, %v", outcome.Result, err)
	}
}

func TestJobReadAdaptersRejectUnknownFieldsAndWrongTargetShapes(t *testing.T) {
	adapters, err := NewJobReadAdapters(&jobReadFake{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := NewRegistry(adapters...)
	list, _ := registry.Lookup("job.list")
	if _, err := list.Decode(json.RawMessage(`{"kind":"job","owner":"acme","name":"job_1"}`), json.RawMessage(`{}`)); err == nil {
		t.Fatal("exact job ID accepted for list")
	}
	if _, err := list.Decode(json.RawMessage(`{"kind":"job","owner":"acme","name":"*"}`), json.RawMessage(`{"token":"secret"}`)); err == nil {
		t.Fatal("unknown argument accepted")
	}
	read, _ := registry.Lookup("job.read")
	if _, err := read.Decode(json.RawMessage(`{"kind":"job","owner":"acme","name":"*"}`), json.RawMessage(`{}`)); err == nil {
		t.Fatal("wildcard accepted for read")
	}
	if _, err := NewJobReadAdapters(nil, time.Now); err == nil {
		t.Fatal("nil client accepted")
	}
	if _, err := NewJobReadAdapters(&jobReadFake{}, nil); err == nil {
		t.Fatal("nil clock accepted")
	}
}

func TestSafeJobStateIncludesUnknown(t *testing.T) {
	want := map[string]string{
		"SCHEDULING": "pending", "RUNNING": "running", "COMPLETED": "completed", "ERROR": "failed",
		"CANCELED": "canceled", "DELETED": "canceled", "PAUSING": "unknown",
	}
	for stage, state := range want {
		if got := safeJobState(stage); got != state {
			t.Fatalf("safeJobState(%q) = %q, want %q", stage, got, state)
		}
	}
}
