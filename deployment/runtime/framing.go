// Package runtime launches signed setup-component adapters over a bounded protocol.
package runtime

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/osolmaz/brokerkit/deployment/api"
	"github.com/osolmaz/brokerkit/internal/strictjson"
)

const maxFrameBytes = api.MaxMessageBytes

// WriteFrame writes one length-prefixed closed JSON message.
func WriteFrame(writer io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > maxFrameBytes {
		return errors.New("setup-component frame exceeds size limit")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data))) // #nosec G115 -- maxFrameBytes is smaller than uint32.
	if _, err := writer.Write(header[:]); err != nil {
		return err
	}
	_, err = writer.Write(data)
	return err
}

// ReadFrame reads one length-prefixed closed JSON message.
func ReadFrame(reader io.Reader, output any) error {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return fmt.Errorf("read setup-component frame header: %w", err)
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > maxFrameBytes {
		return errors.New("setup-component frame size is invalid")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(reader, data); err != nil {
		return fmt.Errorf("read setup-component frame body: %w", err)
	}
	if err := strictjson.Decode(data, output, true); err != nil {
		return fmt.Errorf("decode setup-component frame: %w", err)
	}
	return nil
}
