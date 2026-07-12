// Package plandigest provides content identifiers for immutable broker plans.
package plandigest

import (
	"crypto/sha256"
	"encoding/hex"
)

func Digest(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

func Valid(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
