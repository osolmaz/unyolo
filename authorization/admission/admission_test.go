package admission

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type admissionObserver struct {
	accepted int
	rejected []string
}

func (o *admissionObserver) AdmissionAccepted()            { o.accepted++ }
func (o *admissionObserver) AdmissionRejected(code string) { o.rejected = append(o.rejected, code) }

func TestControllerEnforcesDurableAndProvisionalLimits(t *testing.T) {
	limits := Limits{RequestsPerWindow: 10, Window: time.Minute, ClientActive: 2, ClientPending: 2, GlobalActive: 3, GlobalExecuting: 2}
	usage := Usage{}
	controller, err := newController([]string{"agent", "other"}, limits, func(context.Context, string) (Usage, error) {
		return usage, nil
	}, func() time.Time { return time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	first, err := controller.Admit(t.Context(), "agent")
	if err != nil {
		t.Fatal(err)
	}
	second, err := controller.Admit(t.Context(), "agent")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Admit(t.Context(), "agent"); limitCode(err) != "client_operation_limit" {
		t.Fatalf("third admission = %v", err)
	}
	first.Release()
	second.Commit()
	usage = Usage{ClientPending: 2}
	if _, err := controller.Admit(t.Context(), "agent"); limitCode(err) != "client_pending_limit" {
		t.Fatalf("pending admission = %v", err)
	}
	usage = Usage{GlobalExecuting: 2}
	if _, err := controller.Admit(t.Context(), "other"); limitCode(err) != "global_execution_limit" {
		t.Fatalf("executing admission = %v", err)
	}
}

func TestControllerRateLimitAndFixedClients(t *testing.T) {
	now := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	limits := Limits{RequestsPerWindow: 1, Window: time.Minute, ClientActive: 2, ClientPending: 2, GlobalActive: 2, GlobalExecuting: 2}
	controller, err := newController([]string{"agent"}, limits, func(context.Context, string) (Usage, error) {
		return Usage{}, nil
	}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	observer := &admissionObserver{}
	controller.SetObserver(observer)
	permit, err := controller.Admit(t.Context(), "agent")
	if err != nil {
		t.Fatal(err)
	}
	permit.Release()
	if _, err := controller.Admit(t.Context(), "agent"); limitCode(err) != "submission_rate_limited" {
		t.Fatalf("rate admission = %v", err)
	}
	if _, err := controller.Admit(t.Context(), "unknown"); err == nil {
		t.Fatal("unknown client was admitted")
	}
	now = now.Add(time.Minute)
	if permit, err = controller.Admit(t.Context(), "agent"); err != nil {
		t.Fatal(err)
	}
	permit.Release()
	if observer.accepted != 2 || len(observer.rejected) != 2 || observer.rejected[0] != "submission_rate_limited" || observer.rejected[1] != "client_unconfigured" {
		t.Fatalf("admission observations = %+v", observer)
	}
}

func TestControllerBackwardClockMovementCannotResetRateLimit(t *testing.T) {
	now := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	limits := Limits{RequestsPerWindow: 1, Window: time.Minute, ClientActive: 2, ClientPending: 2, GlobalActive: 2, GlobalExecuting: 2}
	controller, err := newController([]string{"agent"}, limits, func(context.Context, string) (Usage, error) {
		return Usage{}, nil
	}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	permit, err := controller.Admit(t.Context(), "agent")
	if err != nil {
		t.Fatal(err)
	}
	permit.Release()
	now = now.Add(-time.Hour)
	_, err = controller.Admit(t.Context(), "agent")
	var limited *LimitError
	if !errors.As(err, &limited) || limited.Code != "submission_rate_limited" || limited.RetryAfter <= time.Hour {
		t.Fatalf("backward-clock admission = %#v", err)
	}
}

func TestControllerSerializesConcurrentReservations(t *testing.T) {
	limits := Limits{RequestsPerWindow: 10, Window: time.Minute, ClientActive: 1, ClientPending: 1, GlobalActive: 1, GlobalExecuting: 1}
	controller, err := New([]string{"agent"}, limits, func(context.Context, string) (Usage, error) { return Usage{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	wait.Add(2)
	results := make(chan error, 2)
	for range 2 {
		go func() {
			defer wait.Done()
			permit, admitErr := controller.Admit(context.Background(), "agent")
			if admitErr == nil {
				defer permit.Release()
				time.Sleep(20 * time.Millisecond)
			}
			results <- admitErr
		}()
	}
	wait.Wait()
	close(results)
	accepted, refused := 0, 0
	for result := range results {
		if result == nil {
			accepted++
		} else if limitCode(result) == "client_operation_limit" {
			refused++
		}
	}
	if accepted != 1 || refused != 1 {
		t.Fatalf("accepted=%d refused=%d", accepted, refused)
	}
}

func TestControllerRejectsInvalidConfigurationAndUsageFailure(t *testing.T) {
	empty, err := New(nil, DefaultLimits(), func(context.Context, string) (Usage, error) { return Usage{}, nil })
	if err != nil {
		t.Fatalf("empty server admission: %v", err)
	}
	if _, err := empty.Admit(t.Context(), "agent"); err == nil {
		t.Fatal("empty server admitted an unknown client")
	}
	controller, err := New([]string{"agent"}, DefaultLimits(), func(context.Context, string) (Usage, error) {
		return Usage{}, errors.New("offline")
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Admit(t.Context(), "agent"); err == nil {
		t.Fatal("usage failure was ignored")
	}
}

func TestControllerAppliesExactClientOverrides(t *testing.T) {
	config := DefaultConfig()
	config.Clients = map[string]ClientLimits{
		"strict": {RequestsPerWindow: 1, Window: time.Minute, Active: 1, Pending: 1},
	}
	controller, err := newConfiguredController([]string{"strict", "default"}, config,
		func(context.Context, string) (Usage, error) { return Usage{}, nil },
		func() time.Time { return time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	permit, err := controller.Admit(t.Context(), "strict")
	if err != nil {
		t.Fatal(err)
	}
	permit.Release()
	if _, err := controller.Admit(t.Context(), "strict"); limitCode(err) != "submission_rate_limited" {
		t.Fatalf("strict second admission = %v", err)
	}
	permit, err = controller.Admit(t.Context(), "default")
	if err != nil {
		t.Fatalf("default admission = %v", err)
	}
	permit.Release()
}

func limitCode(err error) string {
	var limit *LimitError
	if errors.As(err, &limit) {
		return limit.Code
	}
	return ""
}
