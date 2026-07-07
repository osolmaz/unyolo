package jsend

import "testing"

func TestEnvelopes(t *testing.T) {
	success := Success(map[string]string{"ok": "true"})
	if success.Status != "success" || success.Data == nil {
		t.Fatalf("Success() = %+v", success)
	}

	fail := Fail(map[string]string{"reason": "bad_request"})
	if fail.Status != "fail" || fail.Data == nil {
		t.Fatalf("Fail() = %+v", fail)
	}

	err := Error("could not process request", "internal_error")
	if err.Status != "error" || err.Message != "could not process request" || err.Code != "internal_error" {
		t.Fatalf("Error() = %+v", err)
	}
}
