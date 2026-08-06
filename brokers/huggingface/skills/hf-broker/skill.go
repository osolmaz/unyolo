// Package hfbrokerskill embeds the hf-broker agent skill document so the
// hf-broker binary can print the same SKILL.md that the OpenClaw plugin ships.
package hfbrokerskill

import _ "embed"

// SKILLMD is the bundled hf-broker skill document.
//
//go:embed SKILL.md
var SKILLMD []byte
