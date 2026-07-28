package operations

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/osolmaz/unyolo/internal/strictjson"
)

const (
	maxTargetBytes    = 16 * 1024
	maxArgumentsBytes = 1 << 20
)

func decodeClosed(data json.RawMessage, out any, limit int) error {
	if len(data) == 0 || len(data) > limit {
		return errors.New("JSON object size is invalid")
	}
	return strictjson.Decode(data, out, true)
}

func canonical(value any) (json.RawMessage, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err != nil {
		return nil, err
	}
	return compact.Bytes(), nil
}

func decodeResponse(data json.RawMessage, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("upstream response contains trailing data")
	}
	return nil
}
