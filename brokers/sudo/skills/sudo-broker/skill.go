// Package sudobrokerskill embeds the sudo-broker agent skill document so the
// sudo-broker binary can print the same SKILL.md that the OpenClaw plugin ships.
package sudobrokerskill

import _ "embed"

// SKILLMD is the bundled sudo-broker skill document.
//
//go:embed SKILL.md
var SKILLMD []byte
