package service

import (
	"errors"
	"reflect"
	"testing"
)

func TestInstallTransaction(t *testing.T) {
	writeErr := errors.New("write")
	startErr := errors.New("start")
	readyErr := errors.New("ready")
	tests := []struct {
		name      string
		noStart   bool
		writeErr  error
		startErr  error
		readyErr  error
		wantCalls []string
		wantErr   error
	}{
		{name: "success", wantCalls: []string{"write", "start", "ready", "retire"}},
		{name: "no start", noStart: true, wantCalls: []string{"write"}},
		{name: "write failure", writeErr: writeErr, wantCalls: []string{"write", "restore"}, wantErr: writeErr},
		{name: "start failure", startErr: startErr, wantCalls: []string{"write", "start", "rollback"}, wantErr: startErr},
		{name: "readiness failure", readyErr: readyErr, wantCalls: []string{"write", "start", "ready", "rollback"}, wantErr: readyErr},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := make([]string, 0, len(test.wantCalls))
			call := func(name string, result error) func() error {
				return func() error {
					calls = append(calls, name)
					return result
				}
			}
			transaction := installTransaction{
				write: call("write", test.writeErr), restore: call("restore", nil),
				start: call("start", test.startErr), rollback: call("rollback", nil),
				ready: call("ready", test.readyErr), retire: call("retire", nil), noStart: test.noStart,
			}
			err := transaction.apply()
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("apply() error = %v, want %v", err, test.wantErr)
			}
			if !reflect.DeepEqual(calls, test.wantCalls) {
				t.Fatalf("calls = %v, want %v", calls, test.wantCalls)
			}
		})
	}
}
