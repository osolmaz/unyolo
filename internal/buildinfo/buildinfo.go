// Package buildinfo exposes the release identity embedded in unYOLO binaries.
package buildinfo

// Version is replaced by the release builder. Development binaries remain
// visibly distinct and cannot be mistaken for an attested release.
var Version = "dev"

// SourceCommit is the exact release source digest embedded by the release builder.
var SourceCommit = "dev"

// ID returns the bounded runtime build identity.
func ID() string { return Version }
