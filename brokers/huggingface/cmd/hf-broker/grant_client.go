package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/osolmaz/unyolo/authorization/budget"
	"github.com/osolmaz/unyolo/authorization/client"
	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/opcatalog"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/policy"
	"github.com/osolmaz/unyolo/internal/strictjson"
)

type hfClientGrant struct {
	ID              string           `json:"id"`
	Status          string           `json:"status"`
	Operation       string           `json:"operation"`
	Target          policy.Target    `json:"target"`
	Attrs           map[string]any   `json:"attrs"`
	Mode            policy.GrantMode `json:"mode"`
	Minutes         int              `json:"minutes"`
	MaxUses         usebudget.Limit  `json:"max_uses"`
	UsesRemaining   int              `json:"uses_remaining"`
	UsedCount       int              `json:"used_count"`
	PendingUntil    *string          `json:"pending_until"`
	ExpiresAt       *string          `json:"expires_at"`
	ClientRequestID string           `json:"client_request_id,omitempty"`
}

type hfGrantClient = grantclient.Client[hfClientGrant]

type hfGrantRequest struct {
	Operation       policy.Operation `json:"operation"`
	Target          policy.Target    `json:"target"`
	Attrs           map[string]any   `json:"attrs,omitempty"`
	Minutes         int              `json:"minutes,omitempty"`
	MaxUses         *usebudget.Limit `json:"max_uses,omitempty"`
	Reason          string           `json:"reason"`
	ClientRequestID string           `json:"client_request_id"`
}

type grantRequestOptions struct {
	operation      string
	target         string
	repoType       string
	refs           stringListFlag
	paths          stringListFlag
	keys           stringListFlag
	reason         string
	idempotencyKey string
	minutes        int
	maxUses        optionalUseFlag
	wait           bool
	waitTimeout    time.Duration
	jsonOutput     bool
}

type stringListFlag []string

func (f *stringListFlag) String() string { return strings.Join(*f, ",") }
func (f *stringListFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("value must not be empty")
	}
	*f = append(*f, value)
	return nil
}

type optionalUseFlag struct {
	set   bool
	limit usebudget.Limit
}

func (f *optionalUseFlag) String() string {
	if !f.set {
		return ""
	}
	if f.limit.IsUnlimited() {
		return "unlimited"
	}
	return strconv.Itoa(int(f.limit))
}

func (f *optionalUseFlag) Set(value string) error {
	f.set = true
	if value == "unlimited" {
		f.limit = usebudget.Unlimited
		return nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return errors.New("max uses must be a positive integer or unlimited")
	}
	f.limit = usebudget.Limit(parsed)
	return nil
}

func runClientGrant(ctx context.Context, client *hfGrantClient, stdout, stderr io.Writer, args []string) error {
	if len(args) == 0 {
		return grantClientUsage()
	}
	switch args[0] {
	case "request":
		return runClientGrantRequest(ctx, client, stdout, stderr, args[1:])
	case "get", "wait", "cancel", "revoke":
		return runClientGrantLifecycle(ctx, client, stdout, args[0], args[1:])
	default:
		return grantClientUsage()
	}
}

func runGrantClientFromEnv(ctx context.Context, getenv func(string) string, stdout, stderr io.Writer, args []string) error {
	client, err := loadHFGrantClient(getenv)
	if err != nil {
		return exitError{code: 78, message: err.Error()}
	}
	return runClientGrant(ctx, client, stdout, stderr, args)
}

func grantClientUsage() error {
	return exitError{code: 64, message: "usage: hf-broker client grant request OPERATION OWNER/NAME [options] | hf-broker client grant <get|wait|cancel|revoke> ID"}
}

func runClientGrantRequest(ctx context.Context, client *hfGrantClient, stdout, stderr io.Writer, args []string) error {
	options, err := parseGrantRequestOptions(args)
	if err != nil {
		return exitError{code: 64, message: err.Error()}
	}
	request, err := buildHFGrantRequest(&options)
	if err != nil {
		return exitError{code: 64, message: err.Error()}
	}
	grant, err := requestHFGrant(ctx, client, request, options)
	if err != nil {
		return err
	}
	if !options.jsonOutput {
		_, _ = fmt.Fprintf(stderr, "HF Broker grant %s: %s\n", grant.ID, grant.Status)
	}
	return printHFClientGrant(stdout, grant, options.jsonOutput)
}

func requestHFGrant(ctx context.Context, client *hfGrantClient, request hfGrantRequest, options grantRequestOptions) (hfClientGrant, error) {
	grant, err := client.Request(ctx, request)
	if err != nil {
		return hfClientGrant{}, err
	}
	if options.wait && grant.Status == string(grants.StatusPending) {
		waitCtx, cancel := context.WithTimeout(ctx, options.waitTimeout)
		defer cancel()
		grant, err = client.Wait(waitCtx, grant.ID)
		if err != nil {
			return hfClientGrant{}, err
		}
	}
	return grant, nil
}

func parseGrantRequestOptions(args []string) (grantRequestOptions, error) {
	options := grantRequestOptions{
		repoType: "dataset", reason: "Request temporary Hugging Face access through HF Broker",
		wait: true, waitTimeout: defaultClientWait,
	}
	if len(args) >= 2 && !strings.HasPrefix(args[0], "-") && !strings.HasPrefix(args[1], "-") {
		options.operation, options.target, args = args[0], args[1], args[2:]
	}
	flags := flag.NewFlagSet("grant request", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.repoType, "type", options.repoType, "model, dataset, or space")
	flags.Var(&options.refs, "ref", "exact repository ref; repeatable")
	flags.Var(&options.paths, "path", "repository path scope; repeatable")
	flags.Var(&options.keys, "key", "bucket key scope; repeatable")
	flags.StringVar(&options.reason, "reason", options.reason, "approval reason")
	flags.StringVar(&options.idempotencyKey, "request-id", "", "stable retry key")
	flags.IntVar(&options.minutes, "minutes", 0, "requested duration; omit for policy default")
	flags.Var(&options.maxUses, "max-uses", "positive count or unlimited; omit for policy default")
	flags.BoolVar(&options.wait, "wait", options.wait, "wait for a decision")
	flags.DurationVar(&options.waitTimeout, "wait-timeout", options.waitTimeout, "maximum wait")
	flags.BoolVar(&options.jsonOutput, "json", false, "emit JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return options, errors.New("grant request arguments are invalid")
	}
	return options, validateGrantRequestOptions(options)
}

func validateGrantRequestOptions(options grantRequestOptions) error {
	descriptor, found := opcatalog.ByName(options.operation)
	if !found || options.target == "" {
		return errors.New("a registered operation and OWNER/NAME target are required")
	}
	if err := validateGrantTargetOptions(descriptor, options); err != nil {
		return err
	}
	if options.minutes < 0 || options.waitTimeout <= 0 || strings.TrimSpace(options.reason) == "" {
		return errors.New("minutes, reason, or wait timeout is invalid")
	}
	return nil
}

func validateGrantTargetOptions(descriptor opcatalog.Descriptor, options grantRequestOptions) error {
	switch descriptor.TargetKind {
	case string(policy.KindRepo):
		if !validGrantRepoType(options.repoType) {
			return errors.New("type must be model, dataset, or space")
		}
		if len(options.keys) > 0 {
			return errors.New("repository grant scopes do not accept bucket keys")
		}
	case string(policy.KindBucket):
		if len(options.refs) > 0 || len(options.paths) > 0 {
			return errors.New("bucket grant scopes accept keys, not refs or paths")
		}
	default:
		return errors.New("grant request CLI supports repository and bucket operations")
	}
	return nil
}

func validGrantRepoType(value string) bool {
	return value == string(policy.TypeModel) || value == string(policy.TypeDataset) || value == string(policy.TypeSpace)
}

func buildHFGrantRequest(options *grantRequestOptions) (hfGrantRequest, error) {
	target, err := buildHFGrantTarget(*options)
	if err != nil {
		return hfGrantRequest{}, err
	}
	if options.idempotencyKey == "" {
		options.idempotencyKey, err = randomClientID()
		if err != nil {
			return hfGrantRequest{}, err
		}
	}
	request := hfGrantRequest{
		Operation: policy.Operation(options.operation), Target: target, Minutes: options.minutes,
		Reason: strings.TrimSpace(options.reason), ClientRequestID: options.idempotencyKey,
	}
	if options.maxUses.set {
		value := options.maxUses.limit
		request.MaxUses = &value
	}
	return request, nil
}

func buildHFGrantTarget(options grantRequestOptions) (policy.Target, error) {
	owner, name, err := parseGrantTargetName(options.target)
	if err != nil {
		return policy.Target{}, err
	}
	descriptor, found := opcatalog.ByName(options.operation)
	if !found {
		return policy.Target{}, errors.New("operation is not registered")
	}
	return grantTargetForDescriptor(options, descriptor, owner, name)
}

func parseGrantTargetName(value string) (string, string, error) {
	owner, name, ok := strings.Cut(value, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return "", "", errors.New("target must be OWNER/NAME")
	}
	return owner, name, nil
}

func grantTargetForDescriptor(options grantRequestOptions, descriptor opcatalog.Descriptor, owner, name string) (policy.Target, error) {
	target := policy.Target{Kind: policy.TargetKind(descriptor.TargetKind), Owner: owner, Name: name}
	switch target.Kind {
	case policy.KindRepo:
		target.Type, target.Refs, target.Paths = policy.RepoType(options.repoType), options.refs, options.paths
	case policy.KindBucket:
		target.Keys = options.keys
	case policy.KindInference:
		return policy.Target{}, errors.New("grant target kind is unsupported")
	}
	return target, nil
}

func runClientGrantLifecycle(ctx context.Context, client *hfGrantClient, stdout io.Writer, action string, args []string) error {
	flags := flag.NewFlagSet("grant "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	jsonOutput := flags.Bool("json", false, "emit JSON")
	timeout := flags.Duration("wait-timeout", defaultClientWait, "maximum wait")
	if err := flags.Parse(args); err != nil || flags.NArg() != 1 {
		return exitError{code: 64, message: "grant ID is required"}
	}
	id := flags.Arg(0)
	grant, err := performGrantAction(ctx, client, action, id, *timeout)
	if err != nil {
		return err
	}
	return printHFClientGrant(stdout, grant, *jsonOutput)
}

func performGrantAction(ctx context.Context, client *hfGrantClient, action, id string, timeout time.Duration) (hfClientGrant, error) {
	switch action {
	case "get":
		return client.Get(ctx, id)
	case "cancel":
		return client.Cancel(ctx, id)
	case "revoke":
		return client.Revoke(ctx, id)
	case "wait":
		waitCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return client.Wait(waitCtx, id)
	}
	return hfClientGrant{}, errors.New("unsupported grant action")
}

func printHFClientGrant(stdout io.Writer, grant hfClientGrant, jsonOutput bool) error {
	if jsonOutput {
		return json.NewEncoder(stdout).Encode(grant)
	}
	_, err := fmt.Fprintf(stdout, "%s\t%s\t%s\n", grant.ID, grant.Status, grant.Operation)
	return err
}

func loadHFGrantClient(getenv func(string) string) (*hfGrantClient, error) {
	configured, err := loadHFClientConfig(getenv)
	if err != nil {
		return nil, err
	}
	httpClient, err := configured.HTTPClient()
	if err != nil {
		return nil, err
	}
	return newHFGrantClientWithHTTP(configured.AgentEndpoint, configured.SharedSecret, httpClient)
}

func newHFGrantClient(endpointURI, secret string) (*hfGrantClient, error) {
	return newHFGrantClientWithHTTP(endpointURI, secret, nil)
}

func newHFGrantClientWithHTTP(endpointURI, secret string, provided *http.Client) (*hfGrantClient, error) {
	if provided == nil {
		provided = &http.Client{}
	}
	provided.Timeout = 35 * time.Second
	provided.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return grantclient.New(grantclient.Options[hfClientGrant]{
		Endpoint: endpointURI, Credential: secret,
		HTTPClient: provided,
		Decode:     decodeHFClientGrant,
		Terminal: func(grant hfClientGrant) bool {
			return grant.Status != string(grants.StatusPending)
		},
	})
}

func decodeHFClientGrant(data []byte) (hfClientGrant, error) {
	var response struct {
		Status string `json:"status"`
		Data   struct {
			Grant hfClientGrant `json:"grant"`
		} `json:"data"`
	}
	if err := strictjson.Decode(data, &response, true); err != nil || response.Status != "success" || response.Data.Grant.ID == "" {
		return hfClientGrant{}, errors.New("invalid HF Broker grant response")
	}
	return response.Data.Grant, nil
}
