package policy

import (
	"errors"
	"strings"
	"time"

	"github.com/dutifuldev/gitcba/internal/shared/normalize"
)

type Operation string

const (
	OperationRepoMetadata      Operation = "repo_metadata"
	OperationContentsRead      Operation = "contents_read"
	OperationTreeList          Operation = "tree_list"
	OperationPullRequestDiff   Operation = "pull_request_diff"
	OperationBranchCreate      Operation = "branch_create"
	OperationPullRequestCreate Operation = "pull_request_create"
	OperationContentsWrite     Operation = "contents_write"
)

var pathAllowlistOperations = map[Operation]struct{}{
	OperationContentsRead:  {},
	OperationTreeList:      {},
	OperationContentsWrite: {},
}

var writeOperations = map[Operation]struct{}{
	OperationBranchCreate:      {},
	OperationPullRequestCreate: {},
	OperationContentsWrite:     {},
}

type RepositoryInput struct {
	TenantID     string
	Owner        string
	Name         string
	Private      bool
	CredentialID string
	Policy       RepositoryPolicy
}

type RepositoryPolicy struct {
	AllowedAgents            []string    `json:"allowed_agents"`
	AllowedOperations        []Operation `json:"allowed_operations"`
	AllowedBranches          []string    `json:"allowed_branches"`
	AllowedPaths             []string    `json:"allowed_paths"`
	RequireApprovalForWrites bool        `json:"require_approval_for_writes"`
}

type Repository struct {
	ID           string
	TenantID     string
	Owner        string
	Name         string
	Private      bool
	CredentialID string
	Policy       RepositoryPolicy
	CreatedAt    time.Time
}

type PublicRepository struct {
	ID           string           `json:"id"`
	TenantID     string           `json:"tenant_id"`
	Owner        string           `json:"owner"`
	Name         string           `json:"name"`
	Private      bool             `json:"private"`
	CredentialID string           `json:"credential_id"`
	Policy       RepositoryPolicy `json:"policy"`
	CreatedAt    time.Time        `json:"created_at"`
}

func (r Repository) Public() PublicRepository {
	return PublicRepository{
		ID:           r.ID,
		TenantID:     r.TenantID,
		Owner:        r.Owner,
		Name:         r.Name,
		Private:      r.Private,
		CredentialID: r.CredentialID,
		Policy:       r.Policy.Clone(),
		CreatedAt:    r.CreatedAt,
	}
}

func (p RepositoryPolicy) Clone() RepositoryPolicy {
	return RepositoryPolicy{
		AllowedAgents:            normalizeStrings(p.AllowedAgents),
		AllowedOperations:        normalizeOperations(p.AllowedOperations),
		AllowedBranches:          normalizeStrings(p.AllowedBranches),
		AllowedPaths:             normalizeStrings(p.AllowedPaths),
		RequireApprovalForWrites: p.RequireApprovalForWrites,
	}
}

func (p RepositoryPolicy) Validate() error {
	normalized := p.Clone()
	if len(normalized.AllowedAgents) == 0 {
		return errors.New("policy.allowed_agents is required")
	}
	if err := validateAllowedOperations(normalized.AllowedOperations); err != nil {
		return err
	}
	if err := validateContentPolicy(normalized); err != nil {
		return err
	}
	return validateWritePolicy(normalized)
}

func validateAllowedOperations(operations []Operation) error {
	if len(operations) == 0 {
		return errors.New("policy.allowed_operations is required")
	}
	for _, operation := range operations {
		if err := validateOperation(operation); err != nil {
			return err
		}
	}
	return nil
}

func validateContentPolicy(policy RepositoryPolicy) error {
	if needsPathAllowlist(policy.AllowedOperations) && len(policy.AllowedPaths) == 0 {
		return errors.New("policy.allowed_paths is required for content operations")
	}
	return nil
}

func validateWritePolicy(policy RepositoryPolicy) error {
	if !hasWriteOperation(policy.AllowedOperations) {
		return nil
	}
	if len(policy.AllowedBranches) == 0 {
		return errors.New("policy.allowed_branches is required for write operations")
	}
	if !policy.RequireApprovalForWrites {
		return errors.New("policy.require_approval_for_writes must be true for write operations")
	}
	return nil
}

func validateOperation(operation Operation) error {
	if operationIsSupported(operation) {
		return nil
	}
	return errors.New("unsupported repository operation")
}

func operationIsSupported(operation Operation) bool {
	switch operation {
	case OperationRepoMetadata,
		OperationContentsRead,
		OperationTreeList,
		OperationPullRequestDiff,
		OperationBranchCreate,
		OperationPullRequestCreate,
		OperationContentsWrite:
		return true
	default:
		return false
	}
}

func hasWriteOperation(operations []Operation) bool {
	return containsAnyOperation(operations, writeOperations)
}

func needsPathAllowlist(operations []Operation) bool {
	return containsAnyOperation(operations, pathAllowlistOperations)
}

func containsAnyOperation(operations []Operation, targets map[Operation]struct{}) bool {
	for _, operation := range operations {
		if _, exists := targets[operation]; exists {
			return true
		}
	}
	return false
}

func normalizeStrings(values []string) []string {
	return normalize.Strings(values)
}

func normalizeOperations(values []Operation) []Operation {
	seen := make(map[Operation]struct{}, len(values))
	normalized := make([]Operation, 0, len(values))
	for _, value := range values {
		value = Operation(strings.TrimSpace(string(value)))
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized
}
