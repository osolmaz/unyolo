// Package activation defines provider-neutral, secret-safe approval failures.
package activation

import "errors"

// Code identifies one closed approval failure category.
type Code string

const (
	CodeInvalidNotification    Code = "invalid_notification"
	CodePlanUnavailable        Code = "plan_unavailable"
	CodePlanMismatch           Code = "plan_mismatch"
	CodeCredentialChanged      Code = "credential_changed"
	CodeCredentialInsufficient Code = "credential_insufficient"
	CodeConstraintExceeded     Code = "constraint_exceeded"
	CodeStorageUnavailable     Code = "storage_unavailable"
	CodeTemporarilyUnavailable Code = "temporarily_unavailable"
	CodeInternalError          Code = "internal_error"
)

// Stage identifies the bounded approval stage that failed.
type Stage string

const (
	StageNotification Stage = "notification"
	StagePlan         Stage = "plan"
	StageCredential   Stage = "credential"
	StageConstraints  Stage = "constraints"
	StageStorage      Stage = "storage"
	StageDependency   Stage = "dependency"
	StageInternal     Stage = "internal"
)

type specification struct {
	stage     Stage
	retryable bool
}

var specifications = map[Code]specification{
	CodeInvalidNotification:    {stage: StageNotification},
	CodePlanUnavailable:        {stage: StagePlan},
	CodePlanMismatch:           {stage: StagePlan},
	CodeCredentialChanged:      {stage: StageCredential},
	CodeCredentialInsufficient: {stage: StageCredential},
	CodeConstraintExceeded:     {stage: StageConstraints},
	CodeStorageUnavailable:     {stage: StageStorage, retryable: true},
	CodeTemporarilyUnavailable: {stage: StageDependency, retryable: true},
	CodeInternalError:          {stage: StageInternal, retryable: true},
}

// Failure is safe to classify. Its private cause must never cross a process boundary.
type Failure struct {
	Code      Code
	Stage     Stage
	Retryable bool
	cause     error
}

// New constructs a closed failure. Unknown codes fail closed as internal errors.
func New(code Code, cause error) *Failure {
	spec, ok := specifications[code]
	if !ok {
		return &Failure{Code: CodeInternalError, Stage: StageInternal, Retryable: true, cause: cause}
	}
	return &Failure{Code: code, Stage: spec.stage, Retryable: spec.retryable, cause: cause}
}

func (f *Failure) Error() string {
	if f == nil || f.Code == "" {
		return string(CodeInternalError)
	}
	return string(f.Code)
}

// Unwrap exposes the private cause only to in-process errors.Is/errors.As calls.
func (f *Failure) Unwrap() error {
	if f == nil {
		return nil
	}
	return f.cause
}

// Known reports whether code belongs to the closed activation failure set.
func Known(code Code) bool {
	_, ok := specifications[code]
	return ok
}

// Classify returns a typed failure or a fail-closed internal category.
func Classify(err error) *Failure {
	var failure *Failure
	if errors.As(err, &failure) && failure != nil {
		return failure
	}
	return New(CodeInternalError, err)
}

// As returns the typed failure when err carries one.
func As(err error) (*Failure, bool) {
	var failure *Failure
	ok := errors.As(err, &failure) && failure != nil
	return failure, ok
}
