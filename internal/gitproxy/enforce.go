package gitproxy

import (
	"context"
	"fmt"
	"strings"
)

// Mirror is the mirror behavior required by push enforcement. It is kept
// local to gitproxy so domain enforcement stays independent of net/http.
type Mirror interface {
	Ensure(context.Context) error
	CurrentRef(context.Context, string) (string, bool, error)
	StoreObject(context.Context, string, []byte) (string, error)
	ReadObject(context.Context, string) (string, []byte, bool, error)
	IsAncestor(context.Context, string, string) (bool, error)
	AdvanceRef(context.Context, string, string) error
	DeleteRef(context.Context, string) error
}

// OverrideFunc reports whether a specific ref failure is covered by an
// operator-approved grant.
type OverrideFunc func(Command, string) bool

// RefUpdateKind is the policy-relevant class of one receive-pack command.
type RefUpdateKind string

const (
	RefUpdateAppend         RefUpdateKind = "append"
	RefUpdateHistoryRewrite RefUpdateKind = "history_rewrite"
	RefUpdateRefDelete      RefUpdateKind = "ref_delete"
	RefUpdateTagUpdate      RefUpdateKind = "tag_update"
)

// ClassifiedCommand is one receive-pack command classified for policy.
type ClassifiedCommand struct {
	Command Command
	Kind    RefUpdateKind
}

// CheckPush verifies that the parsed push is append-only against mirror.
func CheckPush(ctx context.Context, req ReceivePackRequest, mirror Mirror) ([]RefFailure, error) {
	return CheckPushWithOverrides(ctx, req, mirror, nil)
}

// ClassifyPush verifies a push enough to classify every ref update for
// policy. Stale client refs and inspection errors are returned as failures.
func ClassifyPush(ctx context.Context, req ReceivePackRequest, mirror Mirror) ([]ClassifiedCommand, []RefFailure, error) {
	if failures := unsupportedStaticFailures(req.Commands); len(failures) > 0 {
		return nil, failures, nil
	}
	if err := mirror.Ensure(ctx); err != nil {
		return nil, nil, err
	}
	if failures, err := preparePushClassification(ctx, req, mirror); err != nil || len(failures) > 0 {
		return nil, failures, err
	}
	classes, failures, err := classifyCommands(ctx, req.Commands, mirror)
	if err != nil {
		return nil, nil, err
	}
	return classes, failures, nil
}

func preparePushClassification(ctx context.Context, req ReceivePackRequest, mirror Mirror) ([]RefFailure, error) {
	if failures, err := checkClientOldValues(ctx, req.Commands, mirror); err != nil || len(failures) > 0 {
		return failures, err
	}
	return storeObjectsForAncestry(ctx, req, mirror)
}

func unsupportedStaticFailures(commands []Command) []RefFailure {
	var failures []RefFailure
	for _, command := range commands {
		if strings.HasPrefix(command.Ref, "refs/replace/") {
			failures = append(failures, RefFailure{Ref: command.Ref, Reason: "replace refs refused"})
		}
	}
	return failures
}

func classifyCommands(ctx context.Context, commands []Command, mirror Mirror) ([]ClassifiedCommand, []RefFailure, error) {
	out := make([]ClassifiedCommand, 0, len(commands))
	var failures []RefFailure
	for _, command := range commands {
		kind, failure, err := classifyCommand(ctx, command, mirror)
		if err != nil {
			return nil, nil, err
		}
		if failure.Reason != "" {
			failures = append(failures, failure)
			continue
		}
		out = append(out, ClassifiedCommand{Command: command, Kind: kind})
	}
	return out, failures, nil
}

func classifyCommand(ctx context.Context, command Command, mirror Mirror) (RefUpdateKind, RefFailure, error) {
	if IsZeroSHA(command.New) {
		return classifyDeletedCommand(command), RefFailure{}, nil
	}
	if updatingExistingTag(command) {
		return RefUpdateTagUpdate, RefFailure{}, nil
	}
	if createsRefOrTag(command) {
		return RefUpdateAppend, RefFailure{}, nil
	}
	return classifyBranchUpdate(ctx, command, mirror)
}

func classifyDeletedCommand(command Command) RefUpdateKind {
	if isTagRef(command.Ref) {
		return RefUpdateTagUpdate
	}
	return RefUpdateRefDelete
}

func updatingExistingTag(command Command) bool {
	return isTagRef(command.Ref) && !IsZeroSHA(command.Old)
}

func createsRefOrTag(command Command) bool {
	return IsZeroSHA(command.Old) || isTagRef(command.Ref)
}

func classifyBranchUpdate(ctx context.Context, command Command, mirror Mirror) (RefUpdateKind, RefFailure, error) {
	ok, err := mirror.IsAncestor(ctx, command.Old, command.New)
	if err != nil {
		return "", RefFailure{}, err
	}
	if !ok {
		return RefUpdateHistoryRewrite, RefFailure{}, nil
	}
	return RefUpdateAppend, RefFailure{}, nil
}

func isTagRef(ref string) bool {
	return strings.HasPrefix(ref, "refs/tags/")
}

// CheckPushWithOverrides verifies a push while allowing selected failures to
// be overridden by an operator grant. Stale client refs and inspection errors
// are never overridden.
func CheckPushWithOverrides(ctx context.Context, req ReceivePackRequest, mirror Mirror, override OverrideFunc) ([]RefFailure, error) {
	if failures := checkStaticWithOverrides(req.Commands, override); len(failures) > 0 {
		return failures, nil
	}
	if err := mirror.Ensure(ctx); err != nil {
		return nil, err
	}
	if failures, err := checkClientOldValues(ctx, req.Commands, mirror); err != nil || len(failures) > 0 {
		return failures, err
	}
	if failures, err := storeObjectsForAncestry(ctx, req, mirror); err != nil || len(failures) > 0 {
		return failures, err
	}
	return checkAncestryWithOverrides(ctx, req.Commands, mirror, override)
}

func checkStaticWithOverrides(commands []Command, override OverrideFunc) []RefFailure {
	return unappliedFailures(commands, CheckStaticRules(commands), override)
}

func storeObjectsForAncestry(ctx context.Context, req ReceivePackRequest, mirror Mirror) ([]RefFailure, error) {
	if !needsAncestryObjects(req.Commands) {
		return nil, nil
	}
	if err := storeIncomingObjects(ctx, req.Pack, mirror); err != nil {
		return failureForAll(req.Commands, "could not inspect incoming pack"), err
	}
	return nil, nil
}

func checkAncestryWithOverrides(ctx context.Context, commands []Command, mirror Mirror, override OverrideFunc) ([]RefFailure, error) {
	failures, err := checkAncestry(ctx, commands, mirror)
	if err != nil {
		return nil, err
	}
	return unappliedFailures(commands, failures, override), nil
}

// AdvanceAccepted updates mirror refs after upstream accepted the push.
func AdvanceAccepted(ctx context.Context, req ReceivePackRequest, mirror Mirror) error {
	for _, command := range req.Commands {
		if IsZeroSHA(command.New) {
			if err := mirror.DeleteRef(ctx, command.Ref); err != nil {
				return err
			}
			continue
		}
		if err := mirror.AdvanceRef(ctx, command.Ref, command.New); err != nil {
			return err
		}
	}
	return nil
}

func checkClientOldValues(ctx context.Context, commands []Command, mirror Mirror) ([]RefFailure, error) {
	var failures []RefFailure
	for _, command := range commands {
		current, exists, err := mirror.CurrentRef(ctx, command.Ref)
		if err != nil {
			return nil, err
		}
		if clientOldStale(command.Old, current, exists) {
			failures = append(failures, RefFailure{Ref: command.Ref, Reason: "client ref is stale"})
		}
	}
	return failures, nil
}

func clientOldStale(old, current string, exists bool) bool {
	switch {
	case IsZeroSHA(old):
		return exists
	case !exists:
		return true
	default:
		return !strings.EqualFold(current, old)
	}
}

func storeIncomingObjects(ctx context.Context, pack []byte, mirror Mirror) error {
	objects, err := extractIncomingObjects(ctx, pack, mirror)
	if err != nil {
		return err
	}
	return storeExtractedObjects(ctx, mirror, objects)
}

func extractIncomingObjects(ctx context.Context, pack []byte, mirror Mirror) ([]GitObject, error) {
	return ExtractCommitAndTagObjects(pack, func(sha string) (GitObject, bool, error) {
		objectType, data, found, err := mirror.ReadObject(ctx, sha)
		if err != nil || !found {
			return GitObject{}, found, err
		}
		return GitObject{Type: objectType, Data: data, SHA: sha}, true, nil
	})
}

func storeExtractedObjects(ctx context.Context, mirror Mirror, objects []GitObject) error {
	for _, object := range objects {
		if err := storeOneObject(ctx, mirror, object); err != nil {
			return err
		}
	}
	return nil
}

func storeOneObject(ctx context.Context, mirror Mirror, object GitObject) error {
	sha, err := mirror.StoreObject(ctx, object.Type, object.Data)
	if err != nil {
		return err
	}
	if !strings.EqualFold(sha, object.SHA) {
		return fmt.Errorf("stored object sha mismatch: expected %s got %s", object.SHA, sha)
	}
	return nil
}

func checkAncestry(ctx context.Context, commands []Command, mirror Mirror) ([]RefFailure, error) {
	var failures []RefFailure
	for _, command := range commands {
		if IsZeroSHA(command.Old) || IsZeroSHA(command.New) || strings.HasPrefix(command.Ref, "refs/tags/") {
			continue
		}
		ok, err := mirror.IsAncestor(ctx, command.Old, command.New)
		if err != nil {
			return nil, err
		}
		if !ok {
			failures = append(failures, RefFailure{Ref: command.Ref, Reason: "history rewrite refused"})
		}
	}
	return failures, nil
}

func needsAncestryObjects(commands []Command) bool {
	for _, command := range commands {
		if !IsZeroSHA(command.Old) && !IsZeroSHA(command.New) && !strings.HasPrefix(command.Ref, "refs/tags/") {
			return true
		}
	}
	return false
}

func failureForAll(commands []Command, reason string) []RefFailure {
	failures := make([]RefFailure, 0, len(commands))
	for _, command := range commands {
		failures = append(failures, RefFailure{Ref: command.Ref, Reason: reason})
	}
	return failures
}

func unappliedFailures(commands []Command, failures []RefFailure, override OverrideFunc) []RefFailure {
	if override == nil || len(failures) == 0 {
		return failures
	}
	commandsByRef := make(map[string]Command, len(commands))
	for _, command := range commands {
		commandsByRef[command.Ref] = command
	}
	var unapplied []RefFailure
	for _, failure := range failures {
		command, ok := commandsByRef[failure.Ref]
		if !ok || !override(command, failure.Reason) {
			unapplied = append(unapplied, failure)
		}
	}
	return unapplied
}
