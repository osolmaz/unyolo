package main

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/internal/host/doctor"
)

func TestParseDoctorOptions(t *testing.T) {
	t.Parallel()
	opts, help, err := parseDoctorOptions([]string{"--agent", "bob", "--json"}, &bytes.Buffer{})
	if err != nil || help || !opts.jsonOutput || opts.agentUser != "bob" {
		t.Fatalf("doctor options = %+v, %t, %v", opts, help, err)
	}
	var helpOutput bytes.Buffer
	if _, help, err := parseDoctorOptions([]string{"--help"}, &helpOutput); err != nil || !help || helpOutput.Len() == 0 {
		t.Fatalf("doctor help=%t err=%v output=%q", help, err, helpOutput.String())
	}
	for _, args := range [][]string{nil, {"--agent", "bob", "--helper-timeout", "0"}, {"--agent", "bob", "--catalog", "relative"}, {"extra", "--agent", "bob"}} {
		if _, _, err := parseDoctorOptions(args, &bytes.Buffer{}); err == nil {
			t.Fatalf("doctor options %v were accepted", args)
		}
	}
}

func TestSudoDoctorReportAggregatesRealBoundaries(t *testing.T) {
	t.Parallel()
	opts := doctorOptions{agentUser: "bob", serviceUser: "sudo-broker", catalogPath: "/catalog", helperState: "/state", helperSocket: "/socket", helperTimeout: time.Second}
	identities := map[string]doctor.Identity{
		"bob": {User: "bob", UID: 1000, GID: 1000}, "sudo-broker": {User: "sudo-broker", UID: 1001, GID: 1001},
	}
	deps := doctorDependencies{
		lookupIdentity:   func(name string) (doctor.Identity, error) { return identities[name], nil },
		validateRootFile: func(string) error { return nil }, validateRootDirectory: func(string) error { return nil },
		validateSocket: func(string, uint32) error { return nil }, kernelSafety: func() (bool, error) { return true, nil },
		helperReady: func(context.Context, string, time.Duration) error { return nil },
	}
	report, err := sudoDoctorReportWith(t.Context(), opts, deps)
	if err != nil || report.Status != doctor.StatusOK || len(report.Checks) != 7 {
		t.Fatalf("doctor report = %+v, %v", report, err)
	}
	deps.kernelSafety = func() (bool, error) { return false, nil }
	report, err = sudoDoctorReportWith(t.Context(), opts, deps)
	if err != nil || report.Status != doctor.StatusOK || report.Checks[5].Status != doctor.CheckWarn {
		t.Fatalf("fallback report = %+v, %v", report, err)
	}
	deps.validateSocket = func(string, uint32) error { return errors.New("unsafe") }
	report, err = sudoDoctorReportWith(t.Context(), opts, deps)
	if err != nil || report.Status != doctor.StatusUnsafe {
		t.Fatalf("unsafe report = %+v, %v", report, err)
	}
	deps.lookupIdentity = func(string) (doctor.Identity, error) { return doctor.Identity{}, errors.New("missing") }
	if _, err := sudoDoctorReportWith(t.Context(), opts, deps); err == nil {
		t.Fatal("identity lookup failure was ignored")
	}
}

func TestDoctorCheckClassificationAndUsage(t *testing.T) {
	t.Parallel()
	if check := hostDoctorCheck("safe", "ok", nil); check.Status != doctor.CheckPass || check.Message != "ok" {
		t.Fatalf("pass check = %+v", check)
	}
	if check := hostDoctorCheck("safe", "ok", errors.New("private detail")); check.Status != doctor.CheckFail || check.Message == "private detail" {
		t.Fatalf("fail check = %+v", check)
	}
	if err := runDoctor(t.Context(), nil, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("missing doctor mode was accepted")
	}
}

func TestRunDoctorWritesReportAndMapsStatus(t *testing.T) {
	t.Parallel()
	provider := func(context.Context, doctorOptions) (doctor.Report, error) {
		return doctor.NewReport(doctor.Identity{User: "bob", UID: 1000}, doctor.Check{Status: doctor.CheckPass, Name: "safe", Message: "safe"}), nil
	}
	var output bytes.Buffer
	if err := runDoctorWithReport(t.Context(), []string{"host", "--agent", "bob", "--json"}, &output, &bytes.Buffer{}, provider); err != nil || !bytes.Contains(output.Bytes(), []byte(`"status": "ok"`)) {
		t.Fatalf("doctor JSON=%q err=%v", output.String(), err)
	}
	unsafeProvider := func(context.Context, doctorOptions) (doctor.Report, error) {
		return doctor.NewReport(doctor.Identity{User: "bob", UID: 1000}, doctor.Check{Status: doctor.CheckFail, Name: "unsafe", Message: "unsafe"}), nil
	}
	if err := runDoctorWithReport(t.Context(), []string{"host", "--agent", "bob"}, &bytes.Buffer{}, &bytes.Buffer{}, unsafeProvider); err == nil {
		t.Fatal("unsafe doctor status did not set an exit error")
	}
	if err := runDoctorWithReport(t.Context(), []string{"host", "--agent", "bob"}, &bytes.Buffer{}, &bytes.Buffer{}, nil); err == nil {
		t.Fatal("nil doctor provider was accepted")
	}
	errorProvider := func(context.Context, doctorOptions) (doctor.Report, error) {
		return doctor.Report{}, errors.New("unavailable")
	}
	if err := runDoctorWithReport(t.Context(), []string{"host", "--agent", "bob"}, &bytes.Buffer{}, &bytes.Buffer{}, errorProvider); err == nil {
		t.Fatal("doctor provider failure was ignored")
	}
}
