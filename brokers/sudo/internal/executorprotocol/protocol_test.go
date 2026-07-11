package executorprotocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestProtocolRoundTrip(t *testing.T) {
	t.Parallel()
	request := Request{Version: Version, Type: TypeExecute, ExecutionID: "execution-1", Plan: json.RawMessage(`{"schema":"sudo-broker.io/plan/v1"}`),
		PlanDigest: strings.Repeat("a", 64), GrantID: "grant-1", ReservationID: "reservation-1", ExpiresAt: time.Now().Add(time.Minute).UTC()}
	var wire bytes.Buffer
	if err := WriteRequest(&wire, request); err != nil {
		t.Fatal(err)
	}
	got, err := ReadRequest(&wire)
	if err != nil || got.ExecutionID != request.ExecutionID || string(got.Plan) != string(request.Plan) {
		t.Fatalf("ReadRequest() = %+v, %v", got, err)
	}
	wire.Reset()
	response := NewCompleted(request.ExecutionID, Outcome{Started: true, ExitCode: 3, Stdout: []byte("out")})
	if err := WriteResponse(&wire, response); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadResponse(&wire)
	if err != nil || decoded.Outcome == nil || decoded.Outcome.ExitCode != 3 {
		t.Fatalf("ReadResponse() = %+v, %v", decoded, err)
	}
}

func TestProtocolRejectsMalformedFrames(t *testing.T) {
	t.Parallel()
	tests := [][]byte{
		frame([]byte(`{"version":1,"version":1,"type":"ping"}`)),
		frame([]byte(`{"version":1,"type":"ping","unknown":true}`)),
		frame([]byte(`{"version":2,"type":"ping"}`)),
		frame([]byte(`{"version":1,"type":"ping"}{}`)),
		{0xff, 0xff, 0xff, 0xff},
	}
	for index, value := range tests {
		if _, err := ReadRequest(bytes.NewReader(value)); err == nil {
			t.Fatalf("case %d was accepted", index)
		}
	}
}

func TestProtocolHandlesShortWrites(t *testing.T) {
	t.Parallel()
	var destination bytes.Buffer
	writer := &shortWriter{destination: &destination}
	if err := WriteRequest(writer, Ping()); err != nil {
		t.Fatal(err)
	}
	request, err := ReadRequest(&destination)
	if err != nil || request.Type != TypePing {
		t.Fatalf("ReadRequest() = %+v, %v", request, err)
	}
}

type shortWriter struct{ destination *bytes.Buffer }

func (w *shortWriter) Write(value []byte) (int, error) {
	return w.destination.Write(value[:min(1, len(value))])
}

func TestProtocolRejectsInvalidResponses(t *testing.T) {
	t.Parallel()
	for _, response := range []Response{
		{Version: Version, Status: StatusReady, ErrorCode: "bad"},
		{Version: Version, Status: StatusCompleted, ExecutionID: "id"},
		{Version: Version, Status: StatusRejected, ErrorCode: "Unsafe-Code"},
		NewCompleted("id", Outcome{Duration: -1}),
		NewCompleted("id", Outcome{Signal: "bad\nsignal"}),
	} {
		var wire bytes.Buffer
		if err := WriteResponse(&wire, response); err == nil {
			t.Fatalf("response was accepted: %+v", response)
		}
	}
}

func frame(data []byte) []byte {
	value := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(value, uint32(len(data)))
	copy(value[4:], data)
	return value
}
