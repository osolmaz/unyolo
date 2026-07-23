// Package xethash validates provider-owned Xet content hashes.
package xethash

import "strings"

// Valid reports whether value is one lowercase 64-character Xet hash.
func Valid(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}
