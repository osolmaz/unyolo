// Package ghbrokerskill embeds the gh-broker agent skill document so the
// gh-broker binary can print the same SKILL.md that the OpenClaw plugin ships.
package ghbrokerskill

import _ "embed"

// SKILLMD is the bundled gh-broker skill document.
//
//go:embed SKILL.md
var SKILLMD []byte
