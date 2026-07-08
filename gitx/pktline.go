// Package gitx contains provider-neutral Git smart-HTTP helpers.
package gitx

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

var ErrFlush = errors.New("pkt-line flush")

// ReadPktLine reads one Git pkt-line payload.
func ReadPktLine(r io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	if string(header) == "0000" {
		return nil, ErrFlush
	}
	lengthBytes, err := hex.DecodeString(string(header))
	if err != nil || len(lengthBytes) != 2 {
		return nil, fmt.Errorf("invalid pkt-line length %q", string(header))
	}
	length := int(lengthBytes[0])<<8 | int(lengthBytes[1])
	if length < 4 {
		return nil, fmt.Errorf("invalid pkt-line length %d", length)
	}
	payload := make([]byte, length-4)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
