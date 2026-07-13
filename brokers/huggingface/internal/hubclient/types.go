package hubclient

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// RepoType is the closed set of repository kinds supported by the typed
// administration methods.
type RepoType string

const (
	RepoTypeModel   RepoType = "model"
	RepoTypeDataset RepoType = "dataset"
	RepoTypeSpace   RepoType = "space"
)

// Visibility is the closed repository visibility vocabulary of the pinned
// upstream client ("protected" applies to Spaces only).
type Visibility string

const (
	VisibilityPublic    Visibility = "public"
	VisibilityPrivate   Visibility = "private"
	VisibilityProtected Visibility = "protected"
)

// GatedMode is the closed gated-access vocabulary. The upstream wire value
// for GatedDisabled is the JSON literal false; GatedUnknown marks an
// unrecognized upstream value and is never sent upstream.
type GatedMode string

const (
	GatedAuto     GatedMode = "auto"
	GatedManual   GatedMode = "manual"
	GatedDisabled GatedMode = "disabled"
	GatedUnknown  GatedMode = "unknown"
)

var namespaceSegmentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$`)

// spaceHardwareFlavors is the closed hardware set from the pinned
// huggingface_hub SpaceHardware enum at commit c4ed724.
var spaceHardwareFlavors = map[string]bool{
	"cpu-basic": true, "cpu-upgrade": true, "zero-a10g": true,
	"t4-small": true, "t4-medium": true,
	"l4x1": true, "l4x4": true, "l40sx1": true, "l40sx4": true, "l40sx8": true,
	"a10g-small": true, "a10g-large": true, "a10g-largex2": true, "a10g-largex4": true,
	"a100-large": true, "a100x4": true, "a100x8": true,
}

// ValidHardwareFlavor reports whether flavor is in the pinned Space hardware
// set.
func ValidHardwareFlavor(flavor string) bool { return spaceHardwareFlavors[flavor] }

// ValidNamespaceSegment reports whether value is a safe owner or repository
// name path segment.
func ValidNamespaceSegment(value string) bool { return namespaceSegmentPattern.MatchString(value) }

// ValidGitRefComponent reports whether value is a safe single git ref name
// (branch or tag). It follows git check-ref-format restrictions for one
// component; slashes are allowed and are always path-escaped on the wire.
//
//nolint:cyclop // Git ref constraints are explicit and tracked by the exact HF CRAP baseline.
func ValidGitRefComponent(value string) bool {
	if value == "" || len(value) > 200 || strings.HasPrefix(value, "-") ||
		strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") ||
		strings.HasSuffix(value, ".lock") || strings.HasSuffix(value, ".") {
		return false
	}
	if strings.Contains(value, "..") || strings.Contains(value, "//") || strings.Contains(value, "@{") {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(" ~^:?*[\\", r) {
			return false
		}
	}
	return true
}

// RepoRef identifies one exact repository.
type RepoRef struct {
	Type  RepoType
	Owner string
	Name  string
}

// Validate rejects unsafe or ambiguous repository identities.
func (r RepoRef) Validate() error {
	if r.Type != RepoTypeModel && r.Type != RepoTypeDataset && r.Type != RepoTypeSpace {
		return errors.New("hubclient: repository type must be model, dataset, or space")
	}
	if !ValidNamespaceSegment(r.Owner) || !ValidNamespaceSegment(r.Name) {
		return errors.New("hubclient: repository owner and name must be exact safe segments")
	}
	return nil
}

// ID returns the owner/name repository identifier.
func (r RepoRef) ID() string { return r.Owner + "/" + r.Name }

// apiPath joins the static per-type API prefix with validated, escaped
// segments. suffix parts must be static literals or pre-escaped values.
func (r RepoRef) apiPath(suffix ...string) string {
	parts := append([]string{
		"/api/" + string(r.Type) + "s", url.PathEscape(r.Owner), url.PathEscape(r.Name),
	}, suffix...)
	return strings.Join(parts, "/")
}

// SpaceRef identifies one exact Space for runtime and settings routes.
type SpaceRef struct {
	Owner string
	Name  string
}

// BucketRef identifies one exact Hub storage bucket.
type BucketRef struct {
	Namespace string
	Name      string
}

func (b BucketRef) Validate() error {
	return validateNamedResource(b.Namespace, b.Name, "hubclient: bucket namespace and name must be exact safe segments")
}

func (b BucketRef) ID() string { return b.Namespace + "/" + b.Name }

func (b BucketRef) apiPath(suffix ...string) string {
	return namedResourcePath("/api/buckets", b.Namespace, b.Name, suffix)
}

// BucketInfo is the bounded bucket state used for operation preconditions.
type BucketInfo struct {
	ID         string  `json:"id"`
	Private    *bool   `json:"private"`
	UpdatedAt  string  `json:"updatedAt"`
	Size       float64 `json:"size"`
	TotalFiles float64 `json:"totalFiles"`
}

// BucketBatchOperation is one content-addressed bucket manifest mutation.
// Content upload happens through the bounded Xet protocol before approval.
type BucketBatchOperation struct {
	Type           string `json:"type"`
	Path           string `json:"path"`
	XetHash        string `json:"xetHash,omitempty"`
	MTime          int64  `json:"mtime,omitempty"`
	ContentType    string `json:"contentType,omitempty"`
	SourceRepoType string `json:"sourceRepoType,omitempty"`
	SourceRepoID   string `json:"sourceRepoId,omitempty"`
}

type CommitOperationKind string

const (
	CommitFile          CommitOperationKind = "file"
	CommitLFSFile       CommitOperationKind = "lfs_file"
	CommitDeletedFile   CommitOperationKind = "deleted_file"
	CommitDeletedFolder CommitOperationKind = "deleted_folder"
)

// CommitOperation is one validated wire operation in a Hub commit.
type CommitOperation struct {
	Kind    CommitOperationKind
	Path    string
	Content []byte
	OID     string
	Size    int64
}

type CommitRequest struct {
	Ref          RepoRef
	Revision     string
	Summary      string
	Description  string
	ParentCommit string
	CreatePR     bool
	HotReload    bool
	Operations   []CommitOperation
}

type CommitResult struct {
	CommitURL      string `json:"commitUrl"`
	CommitOID      string `json:"commitOid"`
	PullRequestURL string `json:"pullRequestUrl"`
}

type RepoPathInfo struct {
	Type    string `json:"type"`
	Path    string `json:"path"`
	OID     string `json:"oid"`
	Size    int64  `json:"size"`
	LFSSHA  string `json:"lfs_sha,omitempty"`
	XetHash string `json:"xet_hash,omitempty"`
}

// Validate rejects unsafe or ambiguous Space identities.
func (s SpaceRef) Validate() error {
	return validateNamedResource(s.Owner, s.Name, "hubclient: space owner and name must be exact safe segments")
}

// ID returns the owner/name Space identifier.
func (s SpaceRef) ID() string { return s.Owner + "/" + s.Name }

func (s SpaceRef) apiPath(suffix ...string) string {
	return namedResourcePath("/api/spaces", s.Owner, s.Name, suffix)
}

func validateNamedResource(owner, name, message string) error {
	if ValidNamespaceSegment(owner) && ValidNamespaceSegment(name) {
		return nil
	}
	return errors.New(message)
}

func namedResourcePath(prefix, owner, name string, suffix []string) string {
	parts := []string{prefix, url.PathEscape(owner), url.PathEscape(name)}
	return strings.Join(append(parts, suffix...), "/")
}

// RepoInfo is the bounded projection of upstream repository metadata used by
// operation preconditions and reconciliation.
type RepoInfo struct {
	ID      string
	SHA     string
	Private bool
	Gated   GatedMode
	SDK     string
}

// RepoSettings is the bounded response from an exact settings mutation.
type RepoSettings struct {
	Visibility Visibility `json:"visibility"`
}

type repoInfoWire struct {
	ID      string          `json:"id"`
	SHA     string          `json:"sha"`
	Private bool            `json:"private"`
	Gated   json.RawMessage `json:"gated"`
	SDK     string          `json:"sdk"`
}

func (w repoInfoWire) toRepoInfo() RepoInfo {
	return RepoInfo{ID: w.ID, SHA: w.SHA, Private: w.Private, Gated: gatedFromWire(w.Gated), SDK: w.SDK}
}

func gatedFromWire(raw json.RawMessage) GatedMode {
	switch strings.TrimSpace(string(raw)) {
	case "", "false", "null":
		return GatedDisabled
	case `"auto"`:
		return GatedAuto
	case `"manual"`:
		return GatedManual
	default:
		return GatedUnknown
	}
}

// GitRef is one branch or tag with its observed target commit.
type GitRef struct {
	Name         string
	Ref          string
	TargetCommit string
}

// Refs lists the observed branches and tags of one repository.
type Refs struct {
	Branches []GitRef
	Tags     []GitRef
}

// Branch returns the named branch, if present.
func (r Refs) Branch(name string) (GitRef, bool) { return findRef(r.Branches, name) }

// Tag returns the named tag, if present.
func (r Refs) Tag(name string) (GitRef, bool) { return findRef(r.Tags, name) }

func findRef(refs []GitRef, name string) (GitRef, bool) {
	for _, ref := range refs {
		if ref.Name == name {
			return ref, true
		}
	}
	return GitRef{}, false
}

type gitRefWire struct {
	Name         string `json:"name"`
	Ref          string `json:"ref"`
	TargetCommit string `json:"targetCommit"`
}

type refsWire struct {
	Branches []gitRefWire `json:"branches"`
	Tags     []gitRefWire `json:"tags"`
}

func (w refsWire) toRefs() Refs {
	return Refs{Branches: refsFromWire(w.Branches), Tags: refsFromWire(w.Tags)}
}

func refsFromWire(values []gitRefWire) []GitRef {
	out := make([]GitRef, 0, len(values))
	for _, value := range values {
		out = append(out, GitRef(value))
	}
	return out
}

// SpaceRuntime is the bounded projection of the upstream Space runtime state.
type SpaceRuntime struct {
	Stage             string
	Hardware          string
	RequestedHardware string
	SleepTimeSeconds  *int
	DevMode           bool
}

type spaceRuntimeWire struct {
	Stage    string `json:"stage"`
	Hardware struct {
		Current   string `json:"current"`
		Requested string `json:"requested"`
	} `json:"hardware"`
	SleepTimeSeconds *int `json:"gcTimeout"`
	DevMode          bool `json:"devMode"`
}

func (w spaceRuntimeWire) toRuntime() SpaceRuntime {
	return SpaceRuntime{Stage: w.Stage, Hardware: w.Hardware.Current, RequestedHardware: w.Hardware.Requested, SleepTimeSeconds: w.SleepTimeSeconds, DevMode: w.DevMode}
}

// SpaceVariable is one non-secret Space environment variable.
type SpaceVariable struct {
	Value       string `json:"value"`
	Description string `json:"description"`
}

// CreatedRepo reports the upstream result of a repository creation.
type CreatedRepo struct {
	URL string `json:"url"`
}

type Identity struct {
	Name string `json:"name"`
}

// CreateRepoInput describes one exact repository creation. Visibility is
// limited to public or private at creation time; protected visibility is a
// separate settings operation.
type CreateRepoInput struct {
	Ref               RepoRef
	Visibility        Visibility
	SpaceSDK          string
	PersonalNamespace bool
}

// spaceSDKs is the closed SPACES_SDK_TYPES set of the pinned upstream client.
var spaceSDKs = map[string]bool{"gradio": true, "streamlit": true, "docker": true, "static": true}

// ValidSpaceSDK reports whether sdk is in the pinned Space SDK set.
func ValidSpaceSDK(sdk string) bool { return spaceSDKs[sdk] }

func (input CreateRepoInput) validate() error {
	if err := input.Ref.Validate(); err != nil {
		return err
	}
	if input.Visibility != VisibilityPublic && input.Visibility != VisibilityPrivate {
		return errors.New("hubclient: repository creation visibility must be public or private")
	}
	if input.Ref.Type == RepoTypeSpace {
		if !ValidSpaceSDK(input.SpaceSDK) {
			return errors.New("hubclient: space SDK must be gradio, streamlit, docker, or static")
		}
	} else if input.SpaceSDK != "" {
		return errors.New("hubclient: SDK applies only to spaces")
	}
	return nil
}

func validateRefName(kind, value string) error {
	if ValidGitRefComponent(value) {
		return nil
	}
	return errors.New("hubclient: " + kind + " name is not a safe git ref")
}
