// Package pktline implements git pkt-line framing: 4 hex digits of total
// length (including the header) followed by the payload, with "0000" as
// the flush packet.
package pktline

import (
	"errors"
	"fmt"
)

// MaxPayload is the largest payload one pkt-line can carry.
const MaxPayload = 65516

// Frame kinds returned by Scanner.Next.
const (
	KindData  = "data"
	KindFlush = "flush"
)

// ErrDone is returned by Scanner.Next when the input is exhausted.
var ErrDone = errors.New("pktline: no more input")

// Scanner walks pkt-line frames over an in-memory buffer and reports the
// byte offset it has consumed, so callers can split framing from a
// trailing raw payload (a packfile, for git-receive-pack).
type Scanner struct {
	data   []byte
	offset int
}

// NewScanner returns a Scanner over data.
func NewScanner(data []byte) *Scanner {
	return &Scanner{data: data}
}

// Offset is the number of bytes consumed so far.
func (s *Scanner) Offset() int {
	return s.offset
}

// Next returns the next frame. For KindData the payload is a sub-slice
// of the input; for KindFlush the payload is nil.
func (s *Scanner) Next() (payload []byte, kind string, err error) {
	if s.offset >= len(s.data) {
		return nil, "", ErrDone
	}
	if len(s.data)-s.offset < 4 {
		return nil, "", errors.New("pktline: truncated length header")
	}
	length, err := parseLength(s.data[s.offset : s.offset+4])
	if err != nil {
		return nil, "", err
	}
	if length == 0 {
		s.offset += 4
		return nil, KindFlush, nil
	}
	if length < 4 || length-4 > MaxPayload {
		return nil, "", fmt.Errorf("pktline: invalid length %d", length)
	}
	end := s.offset + length
	if end > len(s.data) {
		return nil, "", errors.New("pktline: truncated payload")
	}
	payload = s.data[s.offset+4 : end]
	s.offset = end
	return payload, KindData, nil
}

func parseLength(header []byte) (int, error) {
	length := 0
	for _, c := range header {
		digit, err := hexDigit(c)
		if err != nil {
			return 0, err
		}
		length = length<<4 | digit
	}
	return length, nil
}

func hexDigit(c byte) (int, error) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), nil
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, nil
	default:
		return 0, fmt.Errorf("pktline: invalid length digit %q", c)
	}
}

// Append encodes payload as one pkt-line onto dst.
func Append(dst []byte, payload []byte) []byte {
	length := len(payload) + 4
	dst = append(dst, hexChar(length>>12), hexChar(length>>8), hexChar(length>>4), hexChar(length))
	return append(dst, payload...)
}

// AppendString encodes a string payload as one pkt-line onto dst.
func AppendString(dst []byte, payload string) []byte {
	return Append(dst, []byte(payload))
}

// AppendFlush appends a flush packet onto dst.
func AppendFlush(dst []byte) []byte {
	return append(dst, '0', '0', '0', '0')
}

func hexChar(nibble int) byte {
	const digits = "0123456789abcdef"
	return digits[nibble&0xf]
}
