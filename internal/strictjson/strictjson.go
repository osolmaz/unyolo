// Package strictjson provides structural checks missing from encoding/json.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Decode validates and decodes one JSON value. Closed object schemas reject
// unknown fields in addition to duplicate keys and trailing content.
func Decode(data []byte, out any, closed bool) error {
	if err := RejectDuplicateKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if closed {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON content")
		}
		return err
	}
	return nil
}

// RejectDuplicateKeys validates one JSON value and rejects duplicate object keys.
func RejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeValue(decoder, "$"); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON content")
		}
		return err
	}
	return nil
}

func consumeValue(decoder *json.Decoder, path string) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		return consumeObject(decoder, path)
	case '[':
		return consumeArray(decoder, path)
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}

func consumeObject(decoder *json.Decoder, path string) error {
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("JSON object key is not a string")
		}
		if seen[key] {
			return fmt.Errorf("duplicate JSON key %q at %s", key, path)
		}
		seen[key] = true
		if err := consumeValue(decoder, path+"."+key); err != nil {
			return err
		}
	}
	_, err := decoder.Token()
	return err
}

func consumeArray(decoder *json.Decoder, path string) error {
	index := 0
	for decoder.More() {
		if err := consumeValue(decoder, fmt.Sprintf("%s[%d]", path, index)); err != nil {
			return err
		}
		index++
	}
	_, err := decoder.Token()
	return err
}
