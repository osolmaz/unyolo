package doctor

import (
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

const DefaultCredentialRotationAge = 90 * 24 * time.Hour

const (
	CredentialSourceProtectedFile  = "protected-file"
	CredentialSourceInline         = "inline"
	CredentialSourceEncryptedStore = "encrypted-store"

	CredentialRevocationAutomatic = "automatic"
	CredentialRevocationLocal     = "local-only"
	CredentialRevocationManual    = "manual-upstream"
)

// CredentialStatus is secret-safe lifecycle metadata. It never contains a
// credential value, filesystem path, provider target, or raw error.
type CredentialStatus struct {
	Class      string `json:"class"`
	Source     string `json:"source"`
	Age        string `json:"age"`
	Expiry     string `json:"expiry"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	Rotation   string `json:"rotation"`
	Revocation string `json:"revocation"`
}

// CredentialFileStatus inspects only file metadata. The file is never opened.
func CredentialFileStatus(class, path string, now time.Time, rotateAfter time.Duration, expiresAt time.Time, revocation string) CredentialStatus {
	status := baseCredentialStatus(class, CredentialSourceProtectedFile, revocation)
	info, err := os.Stat(path) // #nosec G703 -- doctor inspects an operator-supplied path without opening it.
	if err != nil || !info.Mode().IsRegular() {
		return status
	}
	return credentialStatusAt(status, info.ModTime(), now, rotateAfter, expiresAt)
}

// InlineCredentialStatus reports lifecycle metadata that cannot be proven for
// an inline value without copying that value into the doctor boundary.
func InlineCredentialStatus(class, revocation string) CredentialStatus {
	return baseCredentialStatus(class, CredentialSourceInline, revocation)
}

// StoredCredentialStatus reports metadata supplied by an opaque credential
// store without exposing the stored value.
func StoredCredentialStatus(class string, updatedAt, expiresAt, now time.Time, rotateAfter time.Duration, revocation string) CredentialStatus {
	status := baseCredentialStatus(class, CredentialSourceEncryptedStore, revocation)
	return credentialStatusAt(status, updatedAt, now, rotateAfter, expiresAt)
}

func baseCredentialStatus(class, source, revocation string) CredentialStatus {
	if strings.TrimSpace(revocation) == "" {
		revocation = CredentialRevocationManual
	}
	return CredentialStatus{Class: strings.TrimSpace(class), Source: source, Age: "unknown", Expiry: "not-reported", Rotation: "unknown", Revocation: revocation}
}

func credentialStatusAt(status CredentialStatus, updatedAt, now time.Time, rotateAfter time.Duration, expiresAt time.Time) CredentialStatus {
	now = now.UTC()
	updatedAt = updatedAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	status = credentialAgeStatus(status, updatedAt, now, rotateAfter)
	return credentialExpiryStatus(status, expiresAt, now)
}

func credentialAgeStatus(status CredentialStatus, updatedAt, now time.Time, rotateAfter time.Duration) CredentialStatus {
	if !updatedAt.IsZero() && !updatedAt.After(now) {
		age := now.Sub(updatedAt)
		status.Age = boundedAge(age)
		if rotateAfter > 0 && age >= rotateAfter {
			status.Rotation = "due"
		} else if rotateAfter > 0 {
			status.Rotation = "not-due"
		}
	}
	return status
}

func credentialExpiryStatus(status CredentialStatus, expiresAt, now time.Time) CredentialStatus {
	if !expiresAt.IsZero() {
		expiresAt = expiresAt.UTC()
		status.ExpiresAt = expiresAt.Format(time.RFC3339)
		switch {
		case !expiresAt.After(now):
			status.Expiry = "expired"
			status.Rotation = "due"
		case expiresAt.Sub(now) <= 14*24*time.Hour:
			status.Expiry = "within-14-days"
			status.Rotation = "due"
		default:
			status.Expiry = "valid"
		}
	}
	return status
}

func boundedAge(age time.Duration) string {
	days := int64(age / (24 * time.Hour))
	if days > 9999 {
		return "over-9999-days"
	}
	if days == 1 {
		return "1-day"
	}
	return strconv.FormatInt(days, 10) + "-days"
}

// NormalizeCredentialStatuses removes incomplete entries and returns a stable
// class-sorted report with at most one entry per class.
func NormalizeCredentialStatuses(values []CredentialStatus) []CredentialStatus {
	result := slices.DeleteFunc(slices.Clone(values), func(value CredentialStatus) bool {
		return value.Class == "" || value.Source == ""
	})
	sort.SliceStable(result, func(i, j int) bool { return result[i].Class < result[j].Class })
	return slices.CompactFunc(result, func(left, right CredentialStatus) bool { return left.Class == right.Class })
}
