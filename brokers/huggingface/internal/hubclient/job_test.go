package hubclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestJobClientUsesBoundedRoutesAndSafeProjection(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatal("missing broker credential")
		}
		if r.URL.Path == "/api/jobs/acme" {
			if got := r.URL.Query()["stage"]; !reflect.DeepEqual(got, []string{"RUNNING", "SCHEDULING"}) {
				t.Fatalf("stages = %#v", got)
			}
			if got := r.URL.Query().Get("label"); got != "team=infra" {
				t.Fatalf("label = %q", got)
			}
			if got := r.URL.Query().Get("cursor"); got != "prior" {
				t.Fatalf("cursor = %q", got)
			}
			w.Header().Set("Link", `<`+server.URL+`/api/jobs/acme?cursor=next>; rel="next"`)
			_, _ = w.Write([]byte(`[{"id":"job_1","createdAt":"2026-08-07T12:00:00Z","startedAt":"2026-08-07T12:00:01Z","environment":{"SECRET":"hidden"},"command":["private"],"secrets":["TOKEN"],"flavor":"cpu-basic","owner":{"name":"acme"},"status":{"stage":"RUNNING","message":null}}]`))
			return
		}
		if r.URL.Path == "/api/jobs/acme/job_1" {
			_, _ = w.Write([]byte(`{"id":"job_1","createdAt":"2026-08-07T12:00:00Z","finishedAt":"2026-08-07T12:01:00Z","flavor":"cpu-basic","owner":{"name":"acme"},"status":{"stage":"COMPLETED","message":null}}`))
			return
		}
		t.Fatalf("unexpected request: %s", r.URL.String())
	}))
	defer server.Close()
	client, _ := New(server.URL, "token", WithHTTPTransport(server.Client().Transport))
	page, err := client.ListJobs(context.Background(), "acme", JobListOptions{
		Stages: []string{"SCHEDULING", "RUNNING"}, Labels: map[string]string{"team": "infra"}, Cursor: "prior",
	})
	if err != nil || len(page.Jobs) != 1 || page.NextCursor != "next" || page.Jobs[0].Stage != "RUNNING" {
		t.Fatalf("ListJobs() = %#v, %v", page, err)
	}
	encoded, _ := json.Marshal(page.Jobs[0])
	if string(encoded) != `{"id":"job_1","owner":"acme","stage":"RUNNING","created_at":"2026-08-07T12:00:00Z","started_at":"2026-08-07T12:00:01Z","flavor":"cpu-basic"}` {
		t.Fatalf("safe projection = %s", encoded)
	}
	job, err := client.ReadJob(context.Background(), "acme", "job_1")
	if err != nil || job.Stage != "COMPLETED" || job.FinishedAt == "" {
		t.Fatalf("ReadJob() = %#v, %v", job, err)
	}
}

func TestJobClientRejectsInvalidInputsAndResponses(t *testing.T) {
	client, _ := New("https://huggingface.co", "token")
	if _, err := client.ListJobs(context.Background(), "acme", JobListOptions{Stages: []string{"UNKNOWN"}}); err == nil {
		t.Fatal("invalid stage was accepted")
	}
	if _, err := client.ReadJob(context.Background(), "acme", "bad/id"); err == nil {
		t.Fatal("invalid job ID was accepted")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"different","createdAt":"2026-08-07T12:00:00Z","flavor":"cpu-basic","owner":{"name":"other"},"status":{"stage":"RUNNING"}}`))
	}))
	defer server.Close()
	client, _ = New(server.URL, "token", WithHTTPTransport(server.Client().Transport))
	_, err := client.ReadJob(context.Background(), "acme", "job_1")
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != CodeResponseInvalid {
		t.Fatalf("ReadJob() error = %#v", err)
	}
}

func TestJobClientRejectsUntrustedPaginationLink(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", `<https://attacker.invalid/api/jobs/acme?cursor=stolen>; rel="next"`)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()
	client, _ := New(server.URL, "token", WithHTTPTransport(server.Client().Transport))
	_, err := client.ListJobs(context.Background(), "acme", JobListOptions{})
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != CodeResponseInvalid {
		t.Fatalf("ListJobs() error = %#v", err)
	}
}
