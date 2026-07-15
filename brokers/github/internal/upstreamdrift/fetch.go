package upstreamdrift

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	githubAPI          = "https://api.github.com"
	maxMetadataBytes   = 32 << 20
	metadataUserAgent  = "brokerkit-github-capability-monitor"
	restDirectory      = "descriptions/api.github.com"
	permissionRoot     = "src/github-apps/data"
	apiVersionsPath    = "data/tables/rest-api-versions.yml"
	graphqlSourceURL   = "https://api.github.com/graphql"
	provenanceFileName = "provenance.json"
)

var (
	restVersionName = regexp.MustCompile(`^api\.github\.com\.(\d{4}-\d{2}-\d{2})\.json$`)
	permissionName  = regexp.MustCompile(`^fpt-(\d{4}-\d{2}-\d{2})$`)
	versionDate     = regexp.MustCompile(`['"]?(\d{4}-\d{2}-\d{2})['"]?\s*:`)
	commitPattern   = regexp.MustCompile(`^[a-f0-9]{40}$`)
)

type provenance struct {
	RetrievedAt time.Time            `json:"retrieved_at"`
	Artifacts   []provenanceArtifact `json:"artifacts"`
}

type provenanceArtifact struct {
	Path         string `json:"path"`
	SourceURL    string `json:"source_url"`
	SourceCommit string `json:"source_commit"`
	APIVersion   string `json:"api_version"`
	SHA256       string `json:"sha256"`
}

type remoteEntry struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// Client fetches current official GitHub metadata through fixed source identities.
type Client struct {
	http  *http.Client
	token string
	now   func() time.Time
}

// NewClient returns a bounded upstream metadata client.
func NewClient(token string) *Client {
	return &Client{http: &http.Client{Timeout: 90 * time.Second}, token: strings.TrimSpace(token), now: time.Now}
}

// LoadPinned loads and verifies the reviewed generation inputs.
func LoadPinned(snapshotDirectory string) (SnapshotSet, error) {
	// #nosec G304 -- the caller selects the reviewed snapshot directory and the filename is fixed.
	data, err := os.ReadFile(filepath.Join(snapshotDirectory, provenanceFileName))
	if err != nil {
		return SnapshotSet{}, err
	}
	manifest, err := decodeProvenance(data)
	if err != nil {
		return SnapshotSet{}, err
	}
	set := SnapshotSet{}
	for _, artifact := range manifest.Artifacts {
		if err := loadPinnedArtifact(snapshotDirectory, manifest.RetrievedAt, artifact, &set); err != nil {
			return SnapshotSet{}, err
		}
	}
	if !completeSnapshot(set) {
		return SnapshotSet{}, errors.New("required GitHub snapshots are missing")
	}
	slices.Sort(set.APIVersions)
	set.APIVersions = slices.Compact(set.APIVersions)
	return set, nil
}

func decodeProvenance(data []byte) (provenance, error) {
	var manifest provenance
	if err := json.Unmarshal(data, &manifest); err != nil || len(manifest.Artifacts) < 3 || manifest.RetrievedAt.IsZero() {
		return provenance{}, errors.New("invalid GitHub snapshot provenance")
	}
	return manifest, nil
}

func completeSnapshot(set SnapshotSet) bool {
	return len(set.REST) != 0 && len(set.GraphQL) != 0 && len(set.Permissions) != 0 && len(set.APIVersions) != 0
}

func loadPinnedArtifact(directory string, retrievedAt time.Time, artifact provenanceArtifact, set *SnapshotSet) error {
	if !validRelativePath(artifact.Path) || !validDigest(artifact.SHA256) {
		return fmt.Errorf("invalid pinned artifact identity %q", artifact.Path)
	}
	data, err := readPinnedFile(directory, artifact.Path)
	if err != nil {
		return err
	}
	if digest(data) != artifact.SHA256 {
		return fmt.Errorf("pinned artifact %q failed digest verification", artifact.Path)
	}
	return classifyPinnedArtifact(data, artifact, retrievedAt, set)
}

func readPinnedFile(directory, path string) ([]byte, error) {
	return os.ReadFile(filepath.Join(directory, filepath.FromSlash(path))) // #nosec G304 -- path is traversal-checked.
}

func classifyPinnedArtifact(data []byte, artifact provenanceArtifact, retrievedAt time.Time, set *SnapshotSet) error {
	source := Source{URL: artifact.SourceURL, Commit: artifact.SourceCommit, APIVersion: artifact.APIVersion, SHA256: artifact.SHA256, RetrievedAt: retrievedAt}
	switch {
	case strings.Contains(artifact.SourceURL, "rest-api-description"):
		set.REST, source.Kind = data, "rest"
		if artifact.APIVersion != "" {
			set.APIVersions = append(set.APIVersions, artifact.APIVersion)
		}
	case artifact.SourceURL == graphqlSourceURL:
		set.GraphQL, source.Kind = data, "graphql"
	case strings.Contains(artifact.SourceURL, "server-to-server-permissions.json"):
		set.Permissions, source.Kind = data, "permissions"
	case strings.Contains(artifact.SourceURL, "rest-api-versions.yml"):
		set.APIVersions, source.Kind = extractVersions(data), "api-versions"
	default:
		return nil
	}
	set.Sources = append(set.Sources, source)
	return nil
}

// FetchCurrent resolves immutable commits before downloading official metadata.
func (c *Client) FetchCurrent(ctx context.Context, introspectionQuery []byte) (SnapshotSet, error) {
	if !configuredClient(c) {
		return SnapshotSet{}, errors.New("upstream metadata client is not configured")
	}
	retrievedAt := c.now().UTC()
	rest, restSource, version, err := c.fetchREST(ctx, retrievedAt)
	if err != nil {
		return SnapshotSet{}, err
	}
	permissions, permissionSource, err := c.fetchPermissions(ctx, retrievedAt)
	if err != nil {
		return SnapshotSet{}, err
	}
	versions, versionSource, err := c.fetchAPIVersions(ctx, retrievedAt)
	if err != nil {
		return SnapshotSet{}, err
	}
	graphql, graphqlSource, err := c.fetchGraphQL(ctx, introspectionQuery, retrievedAt)
	if err != nil {
		return SnapshotSet{}, err
	}
	if !slices.Contains(versions, version) {
		return SnapshotSet{}, fmt.Errorf("current REST version %q is absent from official API-version metadata", version)
	}
	return SnapshotSet{
		REST: rest, GraphQL: graphql, Permissions: permissions, APIVersions: versions,
		Sources: []Source{restSource, graphqlSource, permissionSource, versionSource},
	}, nil
}

func configuredClient(client *Client) bool {
	return client != nil && client.http != nil && client.now != nil
}

func (c *Client) fetchREST(ctx context.Context, retrievedAt time.Time) ([]byte, Source, string, error) {
	entries, err := c.listDirectory(ctx, "github", "rest-api-description", restDirectory)
	if err != nil {
		return nil, Source{}, "", fmt.Errorf("list official REST metadata: %w", err)
	}
	name, version, err := latestVersionedEntry(entries, restVersionName, "file")
	if err != nil {
		return nil, Source{}, "", err
	}
	path := restDirectory + "/" + name
	data, source, err := c.fetchRepositoryFile(ctx, "rest", "github", "rest-api-description", path, version, retrievedAt)
	return data, source, version, err
}

func (c *Client) fetchPermissions(ctx context.Context, retrievedAt time.Time) ([]byte, Source, error) {
	entries, err := c.listDirectory(ctx, "github", "docs", permissionRoot)
	if err != nil {
		return nil, Source{}, fmt.Errorf("list official permission metadata: %w", err)
	}
	name, version, err := latestVersionedEntry(entries, permissionName, "dir")
	if err != nil {
		return nil, Source{}, err
	}
	path := permissionRoot + "/" + name + "/server-to-server-permissions.json"
	return c.fetchRepositoryFile(ctx, "permissions", "github", "docs", path, version, retrievedAt)
}

func (c *Client) fetchAPIVersions(ctx context.Context, retrievedAt time.Time) ([]string, Source, error) {
	data, source, err := c.fetchRepositoryFile(ctx, "api-versions", "github", "docs", apiVersionsPath, "", retrievedAt)
	if err != nil {
		return nil, Source{}, err
	}
	versions := extractVersions(data)
	if len(versions) == 0 {
		return nil, Source{}, errors.New("official API-version metadata is empty")
	}
	return versions, source, nil
}

func (c *Client) fetchGraphQL(ctx context.Context, query []byte, retrievedAt time.Time) ([]byte, Source, error) {
	if c.token == "" {
		return nil, Source{}, errors.New("GITHUB_TOKEN is required for GraphQL capability monitoring")
	}
	if len(bytes.TrimSpace(query)) == 0 {
		return nil, Source{}, errors.New("GraphQL introspection query is empty")
	}
	body, err := graphqlRequestBody(query)
	if err != nil {
		return nil, Source{}, err
	}
	data, err := c.request(ctx, http.MethodPost, graphqlSourceURL, bytes.NewReader(body), "application/json")
	if err != nil {
		return nil, Source{}, fmt.Errorf("fetch official GraphQL metadata: %w", err)
	}
	if !validGraphQLResponse(data) {
		return nil, Source{}, errors.New("official GraphQL introspection failed")
	}
	return data, Source{Kind: "graphql", URL: graphqlSourceURL, SHA256: digest(data), RetrievedAt: retrievedAt}, nil
}

func graphqlRequestBody(query []byte) ([]byte, error) {
	return json.Marshal(map[string]string{"query": string(query)})
}

func validGraphQLResponse(data []byte) bool {
	var response struct {
		Errors []json.RawMessage `json:"errors"`
	}
	return json.Unmarshal(data, &response) == nil && len(response.Errors) == 0
}

func (c *Client) listDirectory(ctx context.Context, owner, repository, path string) ([]remoteEntry, error) {
	endpoint := githubAPI + "/repos/" + owner + "/" + repository + "/contents/" + path
	data, err := c.request(ctx, http.MethodGet, endpoint, nil, "")
	if err != nil {
		return nil, err
	}
	var entries []remoteEntry
	if json.Unmarshal(data, &entries) != nil || len(entries) == 0 {
		return nil, errors.New("official repository directory response is invalid")
	}
	return entries, nil
}

func (c *Client) fetchRepositoryFile(ctx context.Context, kind, owner, repository, path, version string, retrievedAt time.Time) ([]byte, Source, error) {
	commit, err := c.resolveCommit(ctx, owner, repository, path)
	if err != nil {
		return nil, Source{}, err
	}
	rawURL := "https://raw.githubusercontent.com/" + owner + "/" + repository + "/" + commit + "/" + path
	data, err := c.request(ctx, http.MethodGet, rawURL, nil, "")
	if err != nil {
		return nil, Source{}, fmt.Errorf("fetch official %s metadata: %w", kind, err)
	}
	return data, Source{Kind: kind, URL: rawURL, Commit: commit, APIVersion: version, SHA256: digest(data), RetrievedAt: retrievedAt}, nil
}

func (c *Client) resolveCommit(ctx context.Context, owner, repository, path string) (string, error) {
	endpoint := githubAPI + "/repos/" + owner + "/" + repository + "/commits?path=" + url.QueryEscape(path) + "&per_page=1"
	data, err := c.request(ctx, http.MethodGet, endpoint, nil, "")
	if err != nil {
		return "", err
	}
	var commits []struct {
		SHA string `json:"sha"`
	}
	if json.Unmarshal(data, &commits) != nil || len(commits) != 1 || !commitPattern.MatchString(commits[0].SHA) {
		return "", errors.New("official source commit response is invalid")
	}
	return commits[0].SHA, nil
}

func (c *Client) request(ctx context.Context, method, endpoint string, body io.Reader, contentType string) ([]byte, error) {
	parsed, err := allowedSource(endpoint)
	if err != nil {
		return nil, err
	}
	request, err := c.newRequest(ctx, method, parsed, body, contentType)
	if err != nil {
		return nil, err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	return readResponse(response)
}

func (c *Client) newRequest(ctx context.Context, method string, endpoint *url.URL, body io.Reader, contentType string) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", metadataUserAgent)
	request.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if c.token != "" && endpoint.Host == "api.github.com" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}
	return request, nil
}

func allowedSource(endpoint string) (*url.URL, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || (parsed.Host != "api.github.com" && parsed.Host != "raw.githubusercontent.com") {
		return nil, errors.New("upstream metadata source is not an allowed official host")
	}
	return parsed, nil
}

func readResponse(response *http.Response) ([]byte, error) {
	if response == nil || response.Body == nil {
		return nil, errors.New("official metadata response is empty")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("official metadata request returned HTTP %d", response.StatusCode)
	}
	return readBounded(response.Body)
}

func readBounded(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxMetadataBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxMetadataBytes {
		return nil, errors.New("official metadata exceeds the byte limit")
	}
	return data, nil
}

func latestVersionedEntry(entries []remoteEntry, pattern *regexp.Regexp, expectedType string) (string, string, error) {
	type candidate struct{ name, version string }
	candidates := make([]candidate, 0)
	for _, entry := range entries {
		match := pattern.FindStringSubmatch(entry.Name)
		if entry.Type == expectedType && len(match) == 2 {
			candidates = append(candidates, candidate{entry.Name, match[1]})
		}
	}
	if len(candidates) == 0 {
		return "", "", errors.New("official versioned metadata entry is missing")
	}
	slices.SortFunc(candidates, func(left, right candidate) int { return strings.Compare(left.version, right.version) })
	latest := candidates[len(candidates)-1]
	return latest.name, latest.version, nil
}

func extractVersions(data []byte) []string {
	matches := versionDate.FindAllSubmatch(data, -1)
	versions := make([]string, 0, len(matches))
	for _, match := range matches {
		versions = append(versions, string(match[1]))
	}
	slices.Sort(versions)
	return slices.Compact(versions)
}

func validRelativePath(path string) bool {
	return path != "" && !filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.HasPrefix(path, "..")
}

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func digest(data []byte) string {
	value := sha256.Sum256(data)
	return hex.EncodeToString(value[:])
}
