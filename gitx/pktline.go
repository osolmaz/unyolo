// Package gitx contains provider-neutral Git smart-HTTP helpers.
package gitx

import (
	"bytes"
	"errors"
	"io"

	gitpktline "github.com/go-git/go-git/v5/plumbing/format/pktline"
)

var (
	ErrFlush = errors.New("pkt-line flush")
	ErrDone  = errors.New("pkt-line input exhausted")
)

const MaxPktLinePayload = gitpktline.MaxPayloadSize

// ReadPktLine reads one Git pkt-line payload.
func ReadPktLine(r io.Reader) ([]byte, error) {
	scanner := gitpktline.NewScanner(r)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, err
		}
		return nil, io.EOF
	}
	if len(scanner.Bytes()) == 0 {
		return nil, ErrFlush
	}
	return append([]byte(nil), scanner.Bytes()...), nil
}

// Scanner reads pkt-lines while retaining the trailing byte offset.
type Scanner struct {
	reader  *bytes.Reader
	scanner *gitpktline.Scanner
}

// NewScanner returns a scanner over an in-memory Git request.
func NewScanner(data []byte) *Scanner {
	reader := bytes.NewReader(data)
	return &Scanner{reader: reader, scanner: gitpktline.NewScanner(reader)}
}

// Offset returns the number of input bytes consumed.
func (s *Scanner) Offset() int64 { return s.reader.Size() - int64(s.reader.Len()) }

// Next returns one payload and reports whether it is a flush packet.
func (s *Scanner) Next() ([]byte, bool, error) {
	if !s.scanner.Scan() {
		if err := s.scanner.Err(); err != nil {
			return nil, false, err
		}
		return nil, false, ErrDone
	}
	if len(s.scanner.Bytes()) == 0 {
		return nil, true, nil
	}
	return s.scanner.Bytes(), false, nil
}

// AppendPktLine appends one encoded pkt-line using go-git's canonical encoder.
func AppendPktLine(dst, payload []byte) ([]byte, error) {
	buffer := bytes.NewBuffer(dst)
	if err := gitpktline.NewEncoder(buffer).Encode(payload); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// AppendPktLineString appends one string payload as a pkt-line.
func AppendPktLineString(dst []byte, payload string) ([]byte, error) {
	return AppendPktLine(dst, []byte(payload))
}

// AppendFlushPkt appends one flush packet.
func AppendFlushPkt(dst []byte) []byte {
	return append(dst, gitpktline.FlushPkt...)
}
