package activation

import (
	"errors"
	"testing"
)

func TestFailureClassification(t *testing.T) {
	cause := errors.New("private detail")
	failure := New(CodeCredentialChanged, cause)
	if failure.Code != CodeCredentialChanged || failure.Stage != StageCredential || failure.Retryable {
		t.Fatalf("failure = %+v", failure)
	}
	if failure.Error() != string(CodeCredentialChanged) || !errors.Is(failure, cause) {
		t.Fatalf("safe error = %q, unwrap=%v", failure.Error(), errors.Is(failure, cause))
	}
	if got := Classify(errors.New("unknown")); got.Code != CodeInternalError || !got.Retryable {
		t.Fatalf("unknown classification = %+v", got)
	}
	if got := New(Code("invalid"), cause); got.Code != CodeInternalError || got.Stage != StageInternal {
		t.Fatalf("invalid code classification = %+v", got)
	}
}
