// Package account provides platform-native account inspection and managed account transactions.
package account

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
)

var namePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}[a-z0-9_$-]$|^[a-z_]$`)

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type Record struct {
	Name   string
	UID    int
	GID    int
	Home   string
	Shell  string
	Groups []string
	Hidden bool
}

type CreatePlan struct {
	Record Record
	System bool
}

type Handle struct {
	Created Record
}

type Backend struct {
	OS     string
	Runner Runner
}

func New(runner Runner) Backend { return Backend{OS: runtime.GOOS, Runner: runner} }

func (backend Backend) List(ctx context.Context) ([]Record, error) {
	if backend.Runner == nil {
		return nil, errors.New("account command runner is required")
	}
	switch backend.OS {
	case "linux":
		output, err := backend.Runner.Run(ctx, "getent", "passwd")
		if err != nil {
			return nil, err
		}
		return parsePasswd(output, 1000), nil
	case "darwin":
		output, err := backend.Runner.Run(ctx, "dscl", ".", "-list", "/Users", "UniqueID")
		if err != nil {
			return nil, err
		}
		return backend.macRecords(ctx, output)
	default:
		return nil, fmt.Errorf("managed accounts are unsupported on %s", backend.OS)
	}
}

func (backend Backend) Inspect(ctx context.Context, name string) (Record, error) {
	if !validName(name) || backend.Runner == nil {
		return Record{}, errors.New("account inspection input is invalid")
	}
	switch backend.OS {
	case "linux":
		output, err := backend.Runner.Run(ctx, "getent", "passwd", name)
		if err != nil {
			return Record{}, err
		}
		records := parsePasswd(output, 0)
		if len(records) != 1 || records[0].Name != name {
			return Record{}, errors.New("account record is unavailable")
		}
		return records[0], nil
	case "darwin":
		return backend.inspectMac(ctx, name)
	default:
		return Record{}, fmt.Errorf("managed accounts are unsupported on %s", backend.OS)
	}
}

func (backend Backend) PlanCreate(name, home string, uid int) (CreatePlan, error) {
	if !validName(name) || !filepath.IsAbs(home) || filepath.Clean(home) != home || home == "/" || home == "/root" {
		return CreatePlan{}, errors.New("managed account identity or home is invalid")
	}
	switch backend.OS {
	case "linux":
		return CreatePlan{Record: Record{Name: name, Home: home, Shell: "/usr/sbin/nologin"}, System: true}, nil
	case "darwin":
		if uid < 501 {
			return CreatePlan{}, errors.New("managed macOS account UID must be at least 501")
		}
		return CreatePlan{Record: Record{Name: name, UID: uid, GID: uid, Home: home, Shell: "/usr/bin/false", Hidden: true}}, nil
	default:
		return CreatePlan{}, fmt.Errorf("managed accounts are unsupported on %s", backend.OS)
	}
}

func (backend Backend) ApplyCreate(ctx context.Context, plan CreatePlan) (Handle, error) {
	if backend.Runner == nil {
		return Handle{}, errors.New("account command runner is required")
	}
	if _, err := backend.Inspect(ctx, plan.Record.Name); err == nil {
		return Handle{}, errors.New("managed account already exists")
	}
	if _, err := os.Lstat(plan.Record.Home); !errors.Is(err, os.ErrNotExist) {
		return Handle{}, errors.New("managed account home already exists or cannot be inspected")
	}
	var err error
	switch backend.OS {
	case "linux":
		_, err = backend.Runner.Run(ctx, "useradd", "--system", "--user-group", "--create-home", "--home-dir", plan.Record.Home, "--shell", plan.Record.Shell, plan.Record.Name)
	case "darwin":
		err = backend.applyMac(ctx, plan.Record)
	default:
		err = fmt.Errorf("managed accounts are unsupported on %s", backend.OS)
	}
	if err != nil {
		return Handle{}, err
	}
	created, err := backend.Inspect(ctx, plan.Record.Name)
	if err != nil {
		return Handle{}, errors.Join(err, backend.delete(ctx, plan.Record))
	}
	if !matches(created, plan.Record) {
		return Handle{}, errors.Join(errors.New("created account does not match the plan"), backend.delete(ctx, created))
	}
	return Handle{Created: created}, nil
}

func (backend Backend) RollbackCreate(ctx context.Context, handle Handle) error {
	current, err := backend.Inspect(ctx, handle.Created.Name)
	if err != nil {
		return err
	}
	if !matches(current, handle.Created) {
		return errors.New("managed account changed after creation")
	}
	if err := safeManagedHome(current.Home); err != nil {
		return err
	}
	return backend.delete(ctx, current)
}

func (backend Backend) Verify(ctx context.Context, expected Record) error {
	current, err := backend.Inspect(ctx, expected.Name)
	if err != nil {
		return err
	}
	if !matches(current, expected) {
		return errors.New("managed account does not match the expected identity")
	}
	return nil
}

func parsePasswd(data []byte, minimumUID int) []Record {
	var records []Record
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			continue
		}
		uid, uidErr := strconv.Atoi(fields[2])
		gid, gidErr := strconv.Atoi(fields[3])
		if uidErr != nil || gidErr != nil || uid < minimumUID || uid == 0 || !validName(fields[0]) || !filepath.IsAbs(fields[5]) || !filepath.IsAbs(fields[6]) {
			continue
		}
		records = append(records, Record{Name: fields[0], UID: uid, GID: gid, Home: filepath.Clean(fields[5]), Shell: filepath.Clean(fields[6])})
	}
	slices.SortFunc(records, func(a, b Record) int { return strings.Compare(a.Name, b.Name) })
	return records
}

func (backend Backend) macRecords(ctx context.Context, data []byte) ([]Record, error) {
	var records []Record
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		uid, err := strconv.Atoi(fields[1])
		if err != nil || uid < 501 || fields[0] == "root" {
			continue
		}
		record, err := backend.inspectMac(ctx, fields[0])
		if err != nil || record.Hidden {
			continue
		}
		records = append(records, record)
	}
	slices.SortFunc(records, func(a, b Record) int { return strings.Compare(a.Name, b.Name) })
	return records, nil
}

func (backend Backend) inspectMac(ctx context.Context, name string) (Record, error) {
	output, err := backend.Runner.Run(ctx, "dscl", ".", "-read", "/Users/"+name, "UniqueID", "PrimaryGroupID", "NFSHomeDirectory", "UserShell", "IsHidden")
	if err != nil {
		return Record{}, err
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		key, value, found := strings.Cut(line, ":")
		if found {
			values[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	uid, uidErr := strconv.Atoi(values["UniqueID"])
	gid, gidErr := strconv.Atoi(values["PrimaryGroupID"])
	if uidErr != nil || gidErr != nil || !filepath.IsAbs(values["NFSHomeDirectory"]) || !filepath.IsAbs(values["UserShell"]) {
		return Record{}, errors.New("macOS account record is invalid")
	}
	return Record{Name: name, UID: uid, GID: gid, Home: filepath.Clean(values["NFSHomeDirectory"]), Shell: filepath.Clean(values["UserShell"]), Hidden: values["IsHidden"] == "1"}, nil
}

func (backend Backend) applyMac(ctx context.Context, record Record) error {
	path := "/Users/" + record.Name
	commands := [][]string{
		{"dscl", ".", "-create", path},
		{"dscl", ".", "-create", path, "UniqueID", strconv.Itoa(record.UID)},
		{"dscl", ".", "-create", path, "PrimaryGroupID", strconv.Itoa(record.GID)},
		{"dscl", ".", "-create", path, "NFSHomeDirectory", record.Home},
		{"dscl", ".", "-create", path, "UserShell", record.Shell},
		{"dscl", ".", "-create", path, "RealName", "unYOLO managed agent"},
		{"dscl", ".", "-create", path, "IsHidden", "1"},
		{"dscl", ".", "-create", path, "AuthenticationAuthority", ";DisabledUser;"},
	}
	for _, command := range commands {
		if _, err := backend.Runner.Run(ctx, command[0], command[1:]...); err != nil {
			_ = backend.delete(ctx, record)
			return err
		}
	}
	if err := os.Mkdir(record.Home, 0o700); err != nil {
		_ = backend.delete(ctx, record)
		return err
	}
	return os.Chown(record.Home, record.UID, record.GID)
}

func (backend Backend) delete(ctx context.Context, record Record) error {
	switch backend.OS {
	case "linux":
		_, err := backend.Runner.Run(ctx, "userdel", "--remove", record.Name)
		return err
	case "darwin":
		_, err := backend.Runner.Run(ctx, "dscl", ".", "-delete", "/Users/"+record.Name)
		return err
	default:
		return fmt.Errorf("managed accounts are unsupported on %s", backend.OS)
	}
}

func safeManagedHome(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || path == "/root" {
		return errors.New("managed account home is unsafe")
	}
	return filepath.WalkDir(path, func(current string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("managed account home contains a symbolic link")
		}
		return nil
	})
}

func matches(actual, expected Record) bool {
	uidMatches := expected.UID == 0 || actual.UID == expected.UID
	gidMatches := expected.GID == 0 || actual.GID == expected.GID
	return actual.Name == expected.Name && uidMatches && gidMatches && actual.Home == expected.Home && actual.Shell == expected.Shell && actual.Hidden == expected.Hidden
}
func validName(value string) bool { return namePattern.MatchString(value) }
