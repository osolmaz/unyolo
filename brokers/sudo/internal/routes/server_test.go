package routes

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorclient"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorprotocol"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/sudopolicy"
	"github.com/osolmaz/brokerkit/conformance"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/operatorclient"
	"github.com/osolmaz/brokerkit/operatorv1"
	corepolicy "github.com/osolmaz/brokerkit/policy"
)

const (
	testClientSecret   = "sudo-client-secret-abcdefghijklmnopqrstuvwxyz"
	testOperatorSecret = "sudo-operator-secret-abcdefghijklmnopqrstuvwxyz"
)

func TestRequestApproveAndExecuteExactCommand(t *testing.T) {
	t.Parallel()
	server, helper, logs := testServer(t)
	agent := httptest.NewServer(server.Handler())
	defer agent.Close()
	operator := httptest.NewServer(server.OperatorHandler())
	defer operator.Close()

	requestBody := `{"client_request_id":"request-1","command_id":"scale","target_user":"root","arguments":{"replicas":2},"reason":"scale release","minutes":2}`
	response := agentRequest(t, agent, http.MethodPost, "/api/v1/requests", requestBody)
	if response.Code != http.StatusCreated {
		t.Fatalf("request status=%d body=%s", response.Code, response.Body.String())
	}
	var created struct {
		Request requestView `json:"request"`
	}
	decodeRecorder(t, response, &created)
	client := &operatorclient.Client{BaseURL: operator.URL, Token: testOperatorSecret, HTTPClient: operator.Client()}
	page, err := client.List(t.Context(), operatorv1.Query{Status: grants.StatusGroupPending})
	if err != nil || len(page.Requests) != 1 {
		t.Fatalf("operator list=%+v err=%v", page, err)
	}
	approved, err := client.Decide(t.Context(), created.Request.ID, operatorv1.ActionApprove, operatorv1.Decision{
		ExpectedRevision: page.Requests[0].Revision, IdempotencyKey: "approve-request-1",
	})
	if err != nil || approved.Status != grants.StatusActive {
		t.Fatalf("approve=%+v err=%v", approved, err)
	}
	execution := agentRequest(t, agent, http.MethodPost, "/api/v1/executions", `{"execution_id":"execution-1","command_id":"scale","target_user":"root","arguments":{"replicas":2}}`)
	if execution.Code != http.StatusOK {
		t.Fatalf("execution status=%d body=%s", execution.Code, execution.Body.String())
	}
	var result struct {
		Execution map[string]any `json:"execution"`
	}
	decodeRecorder(t, execution, &result)
	stdout, _ := base64.StdEncoding.DecodeString(result.Execution["stdout_base64"].(string))
	if string(stdout) != "scaled" || helper.executions != 1 {
		t.Fatalf("execution=%+v helper calls=%d", result, helper.executions)
	}
	stored, err := server.grants.Get(created.Request.ID)
	if err != nil || stored.Status != grants.StatusConsumed {
		t.Fatalf("stored grant=%+v err=%v", stored, err)
	}
	if strings.Contains(logs.String(), "sudo-client-secret") || strings.Contains(logs.String(), "scaled") {
		t.Fatalf("audit leaked secret or output: %s", logs.String())
	}
}

func TestExecutionMismatchAndAmbiguityFailClosed(t *testing.T) {
	t.Parallel()
	server, helper, _ := testServer(t)
	grant := requestAndApprove(t, server)
	agent := httptest.NewServer(server.Handler())
	defer agent.Close()
	mismatch := agentRequest(t, agent, http.MethodPost, "/api/v1/executions", `{"execution_id":"execution-wrong","command_id":"scale","target_user":"root","arguments":{"replicas":3}}`)
	if mismatch.Code != http.StatusForbidden || helper.executions != 0 {
		t.Fatalf("mismatch status=%d helper calls=%d", mismatch.Code, helper.executions)
	}
	helper.status = executorprotocol.StatusAmbiguous
	ambiguous := agentRequest(t, agent, http.MethodPost, "/api/v1/executions", `{"execution_id":"execution-ambiguous","command_id":"scale","target_user":"root","arguments":{"replicas":2}}`)
	if ambiguous.Code != http.StatusServiceUnavailable {
		t.Fatalf("ambiguous status=%d body=%s", ambiguous.Code, ambiguous.Body.String())
	}
	stored, _ := server.grants.Get(grant.ID)
	if !stored.ReservationRetained || stored.UsedCount != 0 {
		t.Fatalf("ambiguous grant=%+v", stored)
	}
}

func TestAgentRoutesRejectUnknownDuplicateAndWrongCredentials(t *testing.T) {
	t.Parallel()
	server, _, _ := testServer(t)
	agent := httptest.NewServer(server.Handler())
	defer agent.Close()
	for _, body := range []string{
		`{"client_request_id":"x","client_request_id":"y","command_id":"scale","target_user":"root","arguments":{"replicas":2},"reason":"test"}`,
		`{"client_request_id":"x","command_id":"scale","target_user":"root","arguments":{"replicas":2},"reason":"test","shell":"/bin/sh"}`,
	} {
		response := agentRequest(t, agent, http.MethodPost, "/api/v1/requests", body)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body=%s status=%d", body, response.Code)
		}
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, agent.URL+"/api/v1/requests", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer wrong-secret-abcdefghijklmnopqrstuvwxyz")
	response, err := agent.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong credential status=%d", response.StatusCode)
	}
}

func TestSudoBrokerOperatorV1Conformance(t *testing.T) {
	t.Parallel()
	server, _, _ := testServer(t)
	resolved, _ := server.catalog.Resolve("scale", "root", map[string]json.RawMessage{"replicas": json.RawMessage(`2`)})
	policyRequest := sudopolicy.Request("bob", resolved)
	request := grants.Request{Client: "bob", ClientRequestID: "conformance", Operation: policyRequest.Operation, Target: policyRequest.Target,
		Attrs: policyRequest.Attrs, Reason: "conformance", Duration: time.Minute, PendingTimeout: time.Minute, MaxUses: 1}
	value, err := plan.Build(request, resolved, plan.Identity{Name: "root", UID: 0, GID: 0}, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := server.plans.Bind(&request, value); err != nil {
		t.Fatal(err)
	}
	conformance.RunOperatorV1(t, conformance.Fixture{Runtime: server.control, Request: request, ClientToken: testClientSecret, OperatorToken: testOperatorSecret})
}

func testServer(t *testing.T) (*Server, *fakeHelper, *bytes.Buffer) {
	t.Helper()
	directory := t.TempDir()
	snapshot, err := catalog.Parse([]byte(fmt.Sprintf(`{"version":1,"commands":[{
		"id":"scale","executable":"/usr/bin/printf","arguments":[{"literal":"%%s"},{"slot":"replicas","type":"integer","minimum":1,"maximum":4}],
		"target_users":["root"],"working_directory":%q,"timeout_seconds":5,"max_output_bytes":100,"risk":"high"}]}`, directory)))
	if err != nil {
		t.Fatal(err)
	}
	policyDocument := `{"rules":[{"id":"request-scale","effect":"request","clients":["bob"],"operations":["exec.command"],
		"targets":[{"kind":"user","name":"root"}],"attrs":{"command_id":["scale"],"argument.replicas":["2"]},
		"grant_policy":{"mode":"execution","default_minutes":2,"max_minutes":5,"request_ttl_minutes":2,"default_max_uses":1,"max_uses":1}}]}`
	brokerPolicy, err := corepolicy.Parse([]byte(policyDocument), sudopolicy.Registry(snapshot))
	if err != nil {
		t.Fatal(err)
	}
	helper := &fakeHelper{status: executorprotocol.StatusCompleted}
	client := &executorclient.Client{SocketPath: "/fake/helper.sock", Dial: helper.dial}
	grantStore := grants.New(filepath.Join(directory, "grants.json"), grants.Options{Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }})
	plans, _ := plan.NewStore(filepath.Join(directory, "plans"))
	var logs bytes.Buffer
	server, err := New(Options{Policy: brokerPolicy, Catalog: snapshot, GrantStore: grantStore, PlanStore: plans,
		Identities: fakeIdentities{}, Helper: client, ClientSecrets: map[string]string{"bob": testClientSecret},
		OperatorSecrets: map[string]string{"onur": testOperatorSecret}, Audit: audit.New(&logs),
		Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }, OperatorConfigured: true})
	if err != nil {
		t.Fatal(err)
	}
	return server, helper, &logs
}

func requestAndApprove(t *testing.T, server *Server) grants.Grant {
	t.Helper()
	resolved, _ := server.catalog.Resolve("scale", "root", map[string]json.RawMessage{"replicas": json.RawMessage(`2`)})
	policyRequest := sudopolicy.Request("bob", resolved)
	request := grants.Request{Client: "bob", ClientRequestID: "direct-test", Operation: policyRequest.Operation, Target: policyRequest.Target,
		Attrs: policyRequest.Attrs, Reason: "test", Duration: time.Minute, PendingTimeout: time.Minute, MaxUses: 1}
	value, _ := plan.Build(request, resolved, plan.Identity{Name: "root", UID: 0, GID: 0}, time.Unix(1_700_000_000, 0))
	_ = server.plans.Bind(&request, value)
	created, _, err := server.grants.Request(request)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := server.control.Decisions.Decide(t.Context(), created.Grant.ID, operatorv1.ActionApprove, "test", operatorv1.Decision{
		ExpectedRevision: created.Grant.Revision, IdempotencyKey: "direct-test-approve",
	})
	if err != nil {
		t.Fatal(err)
	}
	return approved.Grant
}

type fakeIdentities struct{}

func (fakeIdentities) Lookup(string) (plan.Identity, error) {
	return plan.Identity{Name: "root", UID: 0, GID: 0}, nil
}

type fakeHelper struct {
	status     string
	executions int
}

func (f *fakeHelper) dial(_ context.Context, _, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer func() { _ = server.Close() }()
		request, err := executorprotocol.ReadRequest(server)
		if err != nil {
			return
		}
		if request.Type == executorprotocol.TypePing {
			_ = executorprotocol.WriteResponse(server, executorprotocol.Response{Version: executorprotocol.Version, Status: executorprotocol.StatusReady})
			return
		}
		f.executions++
		if f.status == executorprotocol.StatusAmbiguous {
			_ = executorprotocol.WriteResponse(server, executorprotocol.NewAmbiguous(request.ExecutionID, "lost_result"))
			return
		}
		_ = executorprotocol.WriteResponse(server, executorprotocol.NewCompleted(request.ExecutionID, executorprotocol.Outcome{Started: true, ExitCode: 0, Stdout: []byte("scaled")}))
	}()
	return client, nil
}

func agentRequest(t *testing.T, server *httptest.Server, method string, path string, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+testClientSecret)
	response := httptest.NewRecorder()
	// Use the in-process handler so tests retain Echo's exact response body.
	server.Config.Handler.ServeHTTP(response, request)
	return response
}

func decodeRecorder(t *testing.T, recorder *httptest.ResponseRecorder, out any) {
	t.Helper()
	if err := json.NewDecoder(recorder.Body).Decode(out); err != nil && err != io.EOF {
		t.Fatal(err)
	}
}
