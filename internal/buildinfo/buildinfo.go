// Package buildinfo exposes the release identity embedded in BrokerKit binaries.
package buildinfo

// Version is replaced by the release builder. Development binaries remain
// visibly distinct and cannot be mistaken for an attested release.
var Version = "dev"

// ID returns the bounded runtime build identity.
func ID() string { return Version }
