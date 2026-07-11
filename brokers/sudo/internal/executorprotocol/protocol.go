// Package executorprotocol defines the bounded frontend-to-helper wire protocol.
package executorprotocol

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/internal/strictjson"
)

const (
	Version      = 1
	MaxFrameSize = 2 << 20
)

const (
	TypePing    = "ping"
	TypeExecute = "execute"
)

const (
	StatusReady     = "ready"
	StatusCompleted = "completed"
	StatusRejected  = "rejected"
	StatusAmbiguous = "ambiguous"
)

type Request struct {
	Version       int             `json:"version"`
	Type          string          `json:"type"`
	ExecutionID   string          `json:"execution_id,omitempty"`
	Plan          json.RawMessage `json:"plan,omitempty"`
	PlanDigest    string          `json:"plan_digest,omitempty"`
	GrantID       string          `json:"grant_id,omitempty"`
	ReservationID string          `json:"reservation_id,omitempty"`
	ExpiresAt     time.Time       `json:"expires_at,omitempty"`
}

type Outcome struct {
	Started   bool          `json:"started"`
	ExitCode  int           `json:"exit_code,omitempty"`
	Signal    string        `json:"signal,omitempty"`
	TimedOut  bool          `json:"timed_out,omitempty"`
	Truncated bool          `json:"truncated,omitempty"`
	Duration  time.Duration `json:"duration_ns,omitempty"`
	Stdout    []byte        `json:"stdout,omitempty"`
	Stderr    []byte        `json:"stderr,omitempty"`
}

type Response struct {
	Version     int      `json:"version"`
	Status      string   `json:"status"`
	ExecutionID string   `json:"execution_id,omitempty"`
	Outcome     *Outcome `json:"outcome,omitempty"`
	ErrorCode   string   `json:"error_code,omitempty"`
}

func Ping() Request { return Request{Version: Version, Type: TypePing} }

func WriteRequest(writer io.Writer, request Request) error {
	if err := validateRequest(request); err != nil {
		return err
	}
	return writeFrame(writer, request)
}

func ReadRequest(reader io.Reader) (Request, error) {
	var request Request
	if err := readFrame(reader, &request); err != nil {
		return Request{}, err
	}
	if err := validateRequest(request); err != nil {
		return Request{}, err
	}
	return request, nil
}

func WriteResponse(writer io.Writer, response Response) error {
	if err := validateResponse(response); err != nil {
		return err
	}
	return writeFrame(writer, response)
}

func ReadResponse(reader io.Reader) (Response, error) {
	var response Response
	if err := readFrame(reader, &response); err != nil {
		return Response{}, err
	}
	if err := validateResponse(response); err != nil {
		return Response{}, err
	}
	return response, nil
}

func writeFrame(writer io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > MaxFrameSize {
		return errors.New("executor protocol frame is too large")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	if _, err := writer.Write(header[:]); err != nil {
		return err
	}
	_, err = writer.Write(data)
	return err
}

func readFrame(reader io.Reader, out any) error {
	buffered := bufio.NewReader(reader)
	var header [4]byte
	if _, err := io.ReadFull(buffered, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaxFrameSize {
		return errors.New("executor protocol frame size is invalid")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(buffered, data); err != nil {
		return err
	}
	if err := strictjson.RejectDuplicateKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	return nil
}

func validateRequest(request Request) error {
	if request.Version != Version {
		return errors.New("executor protocol version is unsupported")
	}
	switch request.Type {
	case TypePing:
		if request.ExecutionID != "" || len(request.Plan) > 0 || request.PlanDigest != "" || request.GrantID != "" || request.ReservationID != "" || !request.ExpiresAt.IsZero() {
			return errors.New("executor ping contains execution fields")
		}
	case TypeExecute:
		if !boundedID(request.ExecutionID) || len(request.Plan) == 0 || request.PlanDigest == "" || !boundedID(request.GrantID) || !boundedID(request.ReservationID) || request.ExpiresAt.IsZero() {
			return errors.New("executor request is incomplete")
		}
	default:
		return errors.New("executor request type is unsupported")
	}
	return nil
}

func validateResponse(response Response) error {
	if response.Version != Version {
		return errors.New("executor protocol version is unsupported")
	}
	switch response.Status {
	case StatusReady:
		if response.ExecutionID != "" || response.Outcome != nil || response.ErrorCode != "" {
			return errors.New("executor ready response contains result fields")
		}
	case StatusCompleted:
		if !boundedID(response.ExecutionID) || response.Outcome == nil || response.ErrorCode != "" {
			return errors.New("executor completed response is invalid")
		}
	case StatusRejected, StatusAmbiguous:
		if response.Status == StatusAmbiguous && !boundedID(response.ExecutionID) {
			return errors.New("executor ambiguous response is invalid")
		}
		if response.Outcome != nil || !safeCode(response.ErrorCode) {
			return errors.New("executor error response is invalid")
		}
	default:
		return errors.New("executor response status is unsupported")
	}
	return nil
}

func boundedID(value string) bool {
	return len(value) >= 1 && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, " \t\r\n")
}

func safeCode(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func NewRejected(code string) Response {
	return Response{Version: Version, Status: StatusRejected, ErrorCode: code}
}

func NewAmbiguous(executionID string, code string) Response {
	return Response{Version: Version, Status: StatusAmbiguous, ExecutionID: executionID, ErrorCode: code}
}

func NewCompleted(executionID string, outcome Outcome) Response {
	return Response{Version: Version, Status: StatusCompleted, ExecutionID: executionID, Outcome: &outcome}
}
