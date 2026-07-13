package gitx

import (
	"bytes"
	"context"
	"crypto/sha1" // #nosec G505 -- Git pack trailers are SHA-1 by protocol definition.
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/packfile"
	"github.com/go-git/go-git/v5/storage/memory"
)

// PackLimits bounds all work performed while inspecting a SHA-1 packfile.
type PackLimits struct {
	MaxPackBytes     int64
	MaxObjects       uint32
	MaxObjectBytes   int64
	MaxInflatedBytes int64
}

// PackObject is an extracted Git object.
type PackObject struct {
	Type string
	Data []byte
	Hash string
}

// PackBaseReader resolves an object omitted from a thin pack.
type PackBaseReader func(context.Context, string) (PackObject, bool, error)

// ComputeObjectHash returns the canonical SHA-1 identifier for a Git object.
func ComputeObjectHash(objectType string, data []byte) (string, error) {
	typ, err := packObjectType(objectType)
	if err != nil {
		return "", err
	}
	return plumbing.ComputeHash(typ, data).String(), nil
}

// ExtractCommitAndTagObjects validates a SHA-1 pack and returns its commit and
// tag objects. All go-git parsing is contained behind this bounded adapter.
func ExtractCommitAndTagObjects(
	ctx context.Context,
	pack []byte,
	limits PackLimits,
	readBase PackBaseReader,
) ([]PackObject, error) {
	if len(pack) == 0 {
		return nil, nil
	}
	inspection, err := preflightPack(ctx, pack, limits)
	if err != nil {
		return nil, err
	}
	storage := memory.NewStorage()
	if err := loadPackBases(ctx, storage, inspection.refs, limits, inspection.inflated, readBase); err != nil {
		return nil, err
	}
	observer := &objectObserver{ctx: ctx, limits: limits}
	parser, err := packfile.NewParserWithStorage(
		packfile.NewScanner(newContextReadSeeker(ctx, pack)), storage, observer,
	)
	if err != nil {
		return nil, err
	}
	if _, err := parser.Parse(); err != nil {
		return nil, fmt.Errorf("packfile: parse: %w", err)
	}
	return collectPackObjects(storage, observer.objects)
}

type packInspection struct {
	refs     []plumbing.Hash
	inflated int64
}

func preflightPack(ctx context.Context, pack []byte, limits PackLimits) (packInspection, error) {
	if err := validatePackLimits(pack, limits); err != nil {
		return packInspection{}, err
	}
	if err := validatePackBoundary(pack); err != nil {
		return packInspection{}, err
	}
	reader := newContextReadSeeker(ctx, pack)
	scanner := packfile.NewScanner(reader)
	_, count, err := scanner.Header()
	if err != nil {
		return packInspection{}, fmt.Errorf("packfile: header: %w", err)
	}
	if count > limits.MaxObjects {
		return packInspection{}, fmt.Errorf("packfile: object count exceeds %d", limits.MaxObjects)
	}
	inspection, err := inspectPackObjects(scanner, count, limits)
	if err != nil {
		return packInspection{}, err
	}
	if _, err := scanner.Checksum(); err != nil {
		return packInspection{}, fmt.Errorf("packfile: checksum: %w", err)
	}
	return inspection, nil
}

func inspectPackObjects(scanner *packfile.Scanner, count uint32, limits PackLimits) (packInspection, error) {
	inspection := packInspection{refs: make([]plumbing.Hash, 0)}
	for range count {
		ref, inflated, err := inspectPackObject(scanner, limits)
		if err != nil {
			return packInspection{}, err
		}
		inspection.inflated, err = addInflatedBytes(inspection.inflated, inflated, limits.MaxInflatedBytes)
		if err != nil {
			return packInspection{}, err
		}
		if ref != plumbing.ZeroHash {
			inspection.refs = append(inspection.refs, ref)
		}
	}
	return inspection, nil
}

func inspectPackObject(scanner *packfile.Scanner, limits PackLimits) (plumbing.Hash, int64, error) {
	header, err := scanner.NextObjectHeader()
	if err != nil {
		return plumbing.ZeroHash, 0, fmt.Errorf("packfile: object header: %w", err)
	}
	if header.Length < 0 || header.Length > limits.MaxObjectBytes {
		return plumbing.ZeroHash, 0, fmt.Errorf("packfile: object exceeds %d bytes", limits.MaxObjectBytes)
	}
	delta, err := inflatePackObject(scanner, header)
	if err != nil {
		return plumbing.ZeroHash, 0, err
	}
	inflated, err := packObjectInflatedBytes(header, delta, limits)
	if err != nil {
		return plumbing.ZeroHash, 0, err
	}
	if header.Type == plumbing.REFDeltaObject {
		return header.Reference, inflated, nil
	}
	return plumbing.ZeroHash, inflated, nil
}

func inflatePackObject(scanner *packfile.Scanner, header *packfile.ObjectHeader) ([]byte, error) {
	var writer io.Writer
	writer = io.Discard
	var delta bytes.Buffer
	if header.Type.IsDelta() {
		writer = &delta
	}
	written, _, err := scanner.NextObject(writer)
	if err != nil || written != header.Length {
		return nil, fmt.Errorf("packfile: inflate object: %w", errors.Join(err, sizeMismatch(written, header.Length)))
	}
	return delta.Bytes(), nil
}

func packObjectInflatedBytes(header *packfile.ObjectHeader, delta []byte, limits PackLimits) (int64, error) {
	if !header.Type.IsDelta() {
		return header.Length, nil
	}
	targetSize, err := deltaTargetSize(delta, limits.MaxObjectBytes)
	if err != nil {
		return 0, err
	}
	return addInflatedBytes(header.Length, targetSize, limits.MaxInflatedBytes)
}

func validatePackBoundary(pack []byte) error {
	if len(pack) < sha1.Size {
		return errors.New("packfile: truncated checksum")
	}
	checksumAt := len(pack) - sha1.Size
	actual := sha1.Sum(pack[:checksumAt]) // #nosec G401 -- verifies the required Git SHA-1 trailer.
	if !bytes.Equal(actual[:], pack[checksumAt:]) {
		return errors.New("packfile: checksum mismatch or trailing data")
	}
	return nil
}

func validatePackLimits(pack []byte, limits PackLimits) error {
	if limits.MaxPackBytes <= 0 || limits.MaxObjects == 0 || limits.MaxObjectBytes <= 0 || limits.MaxInflatedBytes <= 0 {
		return errors.New("packfile: all limits must be positive")
	}
	if int64(len(pack)) > limits.MaxPackBytes {
		return fmt.Errorf("packfile: input exceeds %d bytes", limits.MaxPackBytes)
	}
	return nil
}

func sizeMismatch(actual, expected int64) error {
	if actual == expected {
		return nil
	}
	return fmt.Errorf("inflated size %d does not match declared size %d", actual, expected)
}

func addInflatedBytes(total, size, maximum int64) (int64, error) {
	if size < 0 || total > maximum-size {
		return 0, fmt.Errorf("packfile: total inflated data exceeds %d bytes", maximum)
	}
	return total + size, nil
}

func deltaTargetSize(delta []byte, maximum int64) (int64, error) {
	_, next, err := deltaSize(delta, 0, maximum)
	if err != nil {
		return 0, err
	}
	target, _, err := deltaSize(delta, next, maximum)
	return target, err
}

func deltaSize(data []byte, offset int, maximum int64) (int64, int, error) {
	var value uint64
	for shift := uint(0); ; shift += 7 {
		if offset >= len(data) || shift >= 63 {
			return 0, 0, errors.New("packfile: invalid delta size")
		}
		current := data[offset]
		offset++
		value |= uint64(current&0x7f) << shift
		if value > math.MaxInt64 {
			return 0, 0, errors.New("packfile: delta size overflows int64")
		}
		converted := int64(value) // #nosec G115 -- value is bounded by math.MaxInt64 above.
		if converted > maximum {
			return 0, 0, fmt.Errorf("packfile: delta object exceeds %d bytes", maximum)
		}
		if current&0x80 == 0 {
			return converted, offset, nil
		}
	}
}

func loadPackBases(
	ctx context.Context,
	storage *memory.Storage,
	refs []plumbing.Hash,
	limits PackLimits,
	inflated int64,
	readBase PackBaseReader,
) error {
	if readBase == nil {
		return nil
	}
	for _, hash := range uniquePackHashes(refs) {
		loaded, size, err := loadPackBase(ctx, storage, hash, limits, readBase)
		if err != nil {
			return err
		}
		if loaded {
			inflated, err = addInflatedBytes(inflated, size, limits.MaxInflatedBytes)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func uniquePackHashes(refs []plumbing.Hash) []plumbing.Hash {
	unique := make([]plumbing.Hash, 0, len(refs))
	seen := make(map[plumbing.Hash]bool, len(refs))
	for _, hash := range refs {
		if !seen[hash] {
			seen[hash] = true
			unique = append(unique, hash)
		}
	}
	return unique
}

func loadPackBase(
	ctx context.Context,
	storage *memory.Storage,
	hash plumbing.Hash,
	limits PackLimits,
	readBase PackBaseReader,
) (bool, int64, error) {
	object, found, err := readBase(ctx, hash.String())
	if err != nil || !found {
		return found, 0, err
	}
	if int64(len(object.Data)) > limits.MaxObjectBytes {
		return false, 0, fmt.Errorf("packfile: external base exceeds %d bytes", limits.MaxObjectBytes)
	}
	if err := storeBaseObject(storage, hash, object); err != nil {
		return false, 0, err
	}
	return true, int64(len(object.Data)), nil
}

func storeBaseObject(storage *memory.Storage, expected plumbing.Hash, object PackObject) error {
	typ, err := packObjectType(object.Type)
	if err != nil {
		return err
	}
	memoryObject := &plumbing.MemoryObject{}
	memoryObject.SetType(typ)
	memoryObject.SetSize(int64(len(object.Data)))
	writer, _ := memoryObject.Writer()
	if _, err := writer.Write(object.Data); err != nil {
		return err
	}
	if memoryObject.Hash() != expected || (object.Hash != "" && !strings.EqualFold(object.Hash, expected.String())) {
		return errors.New("packfile: external base hash mismatch")
	}
	_, err = storage.SetEncodedObject(memoryObject)
	return err
}

type observedObject struct {
	typ  plumbing.ObjectType
	hash plumbing.Hash
}

type objectObserver struct {
	ctx     context.Context
	limits  PackLimits
	current plumbing.ObjectType
	objects []observedObject
}

func (o *objectObserver) OnHeader(count uint32) error {
	if count > o.limits.MaxObjects {
		return fmt.Errorf("packfile: object count exceeds %d", o.limits.MaxObjects)
	}
	return o.ctx.Err()
}

func (o *objectObserver) OnInflatedObjectHeader(typ plumbing.ObjectType, size, _ int64) error {
	if size < 0 || size > o.limits.MaxObjectBytes {
		return fmt.Errorf("packfile: object exceeds %d bytes", o.limits.MaxObjectBytes)
	}
	o.current = typ
	return o.ctx.Err()
}

func (o *objectObserver) OnInflatedObjectContent(hash plumbing.Hash, _ int64, _ uint32, _ []byte) error {
	if o.current == plumbing.CommitObject || o.current == plumbing.TagObject {
		o.objects = append(o.objects, observedObject{typ: o.current, hash: hash})
	}
	return o.ctx.Err()
}

func (o *objectObserver) OnFooter(plumbing.Hash) error { return o.ctx.Err() }

func collectPackObjects(storage *memory.Storage, observed []observedObject) ([]PackObject, error) {
	objects := make([]PackObject, 0, len(observed))
	seen := make(map[plumbing.Hash]bool, len(observed))
	for _, item := range observed {
		if seen[item.hash] {
			continue
		}
		seen[item.hash] = true
		object, err := storage.EncodedObject(item.typ, item.hash)
		if err != nil {
			return nil, err
		}
		reader, err := object.Reader()
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(reader, object.Size()+1))
		closeErr := reader.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			return nil, err
		}
		if int64(len(data)) != object.Size() {
			return nil, errors.New("packfile: extracted object size mismatch")
		}
		objects = append(objects, PackObject{Type: item.typ.String(), Data: data, Hash: item.hash.String()})
	}
	return objects, nil
}

func packObjectType(name string) (plumbing.ObjectType, error) {
	switch name {
	case plumbing.CommitObject.String():
		return plumbing.CommitObject, nil
	case plumbing.TreeObject.String():
		return plumbing.TreeObject, nil
	case plumbing.BlobObject.String():
		return plumbing.BlobObject, nil
	case plumbing.TagObject.String():
		return plumbing.TagObject, nil
	default:
		return plumbing.InvalidObject, fmt.Errorf("packfile: unsupported external object type %q", name)
	}
}

type contextReadSeeker struct {
	ctx    context.Context
	reader *bytes.Reader
}

func newContextReadSeeker(ctx context.Context, data []byte) *contextReadSeeker {
	return &contextReadSeeker{ctx: ctx, reader: bytes.NewReader(data)}
}

func (r *contextReadSeeker) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

func (r *contextReadSeeker) Seek(offset int64, whence int) (int64, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Seek(offset, whence)
}
