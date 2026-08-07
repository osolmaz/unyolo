package httpapi

import (
	"errors"
	"net/http"

	"github.com/osolmaz/unyolo/brokers/huggingface/internal/policy"
	"github.com/osolmaz/unyolo/telemetry/audit"
)

const maxAnonymousGitReadRequestBytes int64 = 8 << 20

var errAnonymousRequestTooLarge = errors.New("anonymous Git read request is too large")

type managedCredentialRequiredError struct {
	status int
}

func (e managedCredentialRequiredError) Error() string {
	return "managed credential may help after anonymous HTTP " + http.StatusText(e.status)
}

func (s *Server) tryAnonymousForward(
	w http.ResponseWriter,
	r *http.Request,
	client string,
	classified classifiedRequest,
	target string,
) (classifiedRequest, bool) {
	if classified.operation != policy.OpGitFetch {
		return classified, false
	}
	request := policy.Request{
		Client: client, Operation: classified.operation, Target: routeTarget(classified.route, nil), Attrs: classified.attrs,
	}
	decision := s.policy.DecideAnonymous(request, s.utcNow())
	if decision.Effect != policy.EffectAllow {
		return classified, false
	}
	prepared, err := prepareAnonymousForwardBody(r, classified)
	if err != nil {
		status := http.StatusBadRequest
		message := "hf-broker: could not read Git request\n"
		if errors.Is(err, errAnonymousRequestTooLarge) {
			status = http.StatusRequestEntityTooLarge
			message = "hf-broker: Git read request is too large\n"
		}
		writePlain(w, status, message)
		s.recordPolicyDecision(client, string(classified.operation), target, audit.DecisionRefused, "could not prepare anonymous Git read", status, decision)
		return prepared, true
	}
	status, forwardErr := s.forwardAnonymous(w, r, client, prepared.route, prepared.body, prepared.bodyRead)
	var credentialRequired managedCredentialRequiredError
	if errors.As(forwardErr, &credentialRequired) {
		s.recordPolicyDecision(client, string(prepared.operation), target, audit.DecisionRefused, "anonymous access did not succeed", status, decision)
		return prepared, false
	}
	if s.recordForwardError(w, client, prepared, target, status, forwardErr, decision) {
		return prepared, true
	}
	s.recordPolicyDecision(client, string(prepared.operation), target, audit.DecisionAllowed, "anonymous upstream access", status, decision)
	return prepared, true
}

func prepareAnonymousForwardBody(r *http.Request, classified classifiedRequest) (classifiedRequest, error) {
	if classified.bodyRead || r.Body == nil || r.Body == http.NoBody {
		return classified, nil
	}
	if r.ContentLength > maxAnonymousGitReadRequestBytes {
		return classified, errAnonymousRequestTooLarge
	}
	body, tooLarge, err := readLimited(r.Body, maxAnonymousGitReadRequestBytes)
	if err != nil {
		return classified, err
	}
	if tooLarge {
		return classified, errAnonymousRequestTooLarge
	}
	classified.body = body
	classified.bodyRead = true
	return classified, nil
}

func anonymousCredentialFallbackStatus(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotFound
}

func stripCredentialHeaders(headers http.Header) {
	for _, key := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Cookie2"} {
		headers.Del(key)
	}
}
