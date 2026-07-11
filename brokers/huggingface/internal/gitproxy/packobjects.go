package gitproxy

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1" // #nosec G505 -- Git object IDs and pack trailers require SHA-1 interoperability.
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const (
	packObjectCommit   = 1
	packObjectTree     = 2
	packObjectBlob     = 3
	packObjectTag      = 4
	packObjectOFSDelta = 6
	packObjectREFDelta = 7

	maxStoredPackObjectBytes = 16 * 1024 * 1024
	maxParsedPackObjects     = 1 << 20
	minPackedObjectBytes     = 9
)

// GitObject is a commit or tag object extracted from an incoming pack.
type GitObject struct {
	Type string
	Data []byte
	SHA  string
}

// BaseObjectReader reads an existing object by SHA from the mirror.
type BaseObjectReader func(sha string) (GitObject, bool, error)

type packedObject struct {
	offset     int
	objectType int
	data       []byte
	baseOffset int
	baseSHA    string
}

type resolvedObject struct {
	objectType int
	data       []byte
	sha        string
}

// ExtractCommitAndTagObjects extracts commit and tag objects from a git
// packfile. Other object types are parsed only as needed to step over
// them; they are not returned or written to the mirror.
func ExtractCommitAndTagObjects(pack []byte, readBase BaseObjectReader) ([]GitObject, error) {
	objects, err := parsePack(pack)
	if err != nil {
		return nil, err
	}
	resolver := newObjectResolver(objects, readBase)
	var extracted []GitObject
	seen := map[string]bool{}
	for i := range objects {
		resolved, ok, err := resolver.resolve(i)
		if err != nil {
			return nil, err
		}
		if !ok || !isCommitOrTag(resolved.objectType) || seen[resolved.sha] {
			continue
		}
		seen[resolved.sha] = true
		extracted = append(extracted, GitObject{
			Type: objectTypeName(resolved.objectType),
			Data: resolved.data,
			SHA:  resolved.sha,
		})
	}
	return extracted, nil
}

func newObjectResolver(objects []packedObject, readBase BaseObjectReader) objectResolver {
	resolver := objectResolver{
		objects:     objects,
		byOffset:    map[int]int{},
		bySHA:       map[string]int{},
		resolved:    map[int]resolvedObject{},
		resolving:   map[int]bool{},
		readBase:    readBase,
		externalSHA: map[string]resolvedObject{},
	}
	for i, object := range objects {
		resolver.byOffset[object.offset] = i
		if isCommitOrTag(object.objectType) && object.data != nil {
			sha := hashObject(object.objectType, object.data)
			resolver.bySHA[sha] = i
		}
	}
	return resolver
}

func parsePack(pack []byte) ([]packedObject, error) {
	count, ok, err := parsePackHeader(pack)
	if err != nil || !ok {
		return nil, err
	}
	if err := validatePackChecksum(pack); err != nil {
		return nil, err
	}
	return parsePackObjects(pack, count)
}

func parsePackHeader(pack []byte) (int, bool, error) {
	if len(pack) == 0 {
		return 0, false, nil
	}
	if len(pack) < 32 || string(pack[:4]) != "PACK" {
		return 0, false, errors.New("packfile: missing PACK header")
	}
	version := binary.BigEndian.Uint32(pack[4:8])
	if version != 2 && version != 3 {
		return 0, false, fmt.Errorf("packfile: unsupported version %d", version)
	}
	return int(binary.BigEndian.Uint32(pack[8:12])), true, nil
}

func validatePackChecksum(pack []byte) error {
	sum := sha1.Sum(pack[:len(pack)-sha1.Size]) // #nosec G401 -- verifies the Git SHA-1 pack trailer.
	if !bytes.Equal(sum[:], pack[len(pack)-sha1.Size:]) {
		return errors.New("packfile: checksum mismatch")
	}
	return nil
}

func parsePackObjects(pack []byte, count int) ([]packedObject, error) {
	payloadBytes := len(pack) - 12 - sha1.Size
	if count > maxParsedPackObjects || count > payloadBytes/minPackedObjectBytes {
		return nil, errors.New("packfile: object count exceeds pack size")
	}
	pos := 12
	objects := make([]packedObject, 0, count)
	for i := 0; i < count; i++ {
		object, next, err := parseOneObject(pack, pos)
		if err != nil {
			return nil, err
		}
		objects = append(objects, object)
		pos = next
	}
	if pos != len(pack)-sha1.Size {
		return nil, errors.New("packfile: trailing data before checksum")
	}
	return objects, nil
}

func parseOneObject(pack []byte, start int) (packedObject, int, error) {
	header, err := parseObjectHeader(pack, start)
	if err != nil {
		return packedObject{}, 0, err
	}
	object := packedObject{offset: start, objectType: header.objectType}
	pos, err := parseObjectBase(pack, header.next, &object)
	if err != nil {
		return packedObject{}, 0, err
	}
	data, next, err := parseObjectData(pack, pos, header)
	if err != nil {
		return packedObject{}, 0, err
	}
	object.data = data
	return object, next, nil
}

func parseObjectData(pack []byte, pos int, header objectHeader) ([]byte, int, error) {
	keepData := shouldKeepPackObjectData(header.objectType)
	if keepData && header.size > maxStoredPackObjectBytes {
		return nil, 0, fmt.Errorf("packfile: inflated object exceeds %d bytes", maxStoredPackObjectBytes)
	}
	data, next, err := inflateObject(pack, pos, header.size, keepData)
	if err != nil {
		return nil, 0, err
	}
	if keepData && uint64(len(data)) != header.size {
		return nil, 0, errors.New("packfile: inflated size mismatch")
	}
	return data, next, nil
}

type objectHeader struct {
	objectType int
	size       uint64
	next       int
}

func parseObjectHeader(pack []byte, start int) (objectHeader, error) {
	if start >= len(pack)-sha1.Size {
		return objectHeader{}, errors.New("packfile: truncated object header")
	}
	pos := start
	first := pack[pos]
	pos++
	objectType := int((first >> 4) & 0x7)
	size := uint64(first & 0x0f)
	shift := uint(4)
	for first&0x80 != 0 {
		if pos >= len(pack)-sha1.Size {
			return objectHeader{}, errors.New("packfile: truncated variable length size")
		}
		first = pack[pos]
		pos++
		size |= uint64(first&0x7f) << shift
		shift += 7
	}
	return objectHeader{objectType: objectType, size: size, next: pos}, nil
}

func parseObjectBase(pack []byte, pos int, object *packedObject) (int, error) {
	if isWholeObject(object.objectType) {
		return pos, nil
	}
	if object.objectType == packObjectOFSDelta {
		return parseObjectOFSBase(pack, pos, object)
	}
	if object.objectType == packObjectREFDelta {
		return parseObjectREFBase(pack, pos, object)
	}
	return 0, fmt.Errorf("packfile: unsupported object type %d", object.objectType)
}

func parseObjectOFSBase(pack []byte, pos int, object *packedObject) (int, error) {
	baseOffset, next, err := parseOFSDeltaBase(pack, pos, object.offset)
	if err != nil {
		return 0, err
	}
	object.baseOffset = baseOffset
	return next, nil
}

func parseObjectREFBase(pack []byte, pos int, object *packedObject) (int, error) {
	if pos+sha1.Size > len(pack)-sha1.Size {
		return 0, errors.New("packfile: truncated ref-delta base")
	}
	object.baseSHA = hex.EncodeToString(pack[pos : pos+sha1.Size])
	return pos + sha1.Size, nil
}

func parseOFSDeltaBase(pack []byte, pos, objectStart int) (int, int, error) {
	if pos >= len(pack)-sha1.Size {
		return 0, 0, errors.New("packfile: truncated ofs-delta base")
	}
	c := pack[pos]
	pos++
	offset := int(c & 0x7f)
	for c&0x80 != 0 {
		if pos >= len(pack)-sha1.Size {
			return 0, 0, errors.New("packfile: truncated ofs-delta base")
		}
		c = pack[pos]
		pos++
		offset = ((offset + 1) << 7) | int(c&0x7f)
	}
	baseOffset := objectStart - offset
	if baseOffset < 12 || baseOffset >= objectStart {
		return 0, 0, errors.New("packfile: invalid ofs-delta base")
	}
	return baseOffset, pos, nil
}

func shouldKeepPackObjectData(objectType int) bool {
	return isCommitOrTag(objectType) || objectType == packObjectOFSDelta || objectType == packObjectREFDelta
}

func inflateObject(pack []byte, pos int, expectedSize uint64, keepData bool) ([]byte, int, error) {
	reader := bytes.NewReader(pack[pos : len(pack)-sha1.Size])
	zreader, err := zlib.NewReader(reader)
	if err != nil {
		return nil, 0, fmt.Errorf("packfile: inflate object: %w", err)
	}
	data, readErr := readInflatedObject(zreader, expectedSize, keepData)
	closeErr := zreader.Close()
	if readErr != nil {
		return nil, 0, fmt.Errorf("packfile: read object: %w", readErr)
	}
	if closeErr != nil {
		return nil, 0, fmt.Errorf("packfile: close object: %w", closeErr)
	}
	consumed := len(pack[pos:len(pack)-sha1.Size]) - reader.Len()
	return data, pos + consumed, nil
}

func readInflatedObject(r io.Reader, expectedSize uint64, keepData bool) ([]byte, error) {
	if !keepData {
		return nil, discardInflatedObject(r, expectedSize)
	}
	limited := io.LimitReader(r, maxStoredPackObjectBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maxStoredPackObjectBytes {
		return nil, fmt.Errorf("inflated object exceeds %d bytes", maxStoredPackObjectBytes)
	}
	return data, nil
}

func discardInflatedObject(reader io.Reader, expectedSize uint64) error {
	if expectedSize > maxStoredPackObjectBytes {
		return fmt.Errorf("inflated object exceeds %d bytes", maxStoredPackObjectBytes)
	}
	written, err := io.Copy(io.Discard, io.LimitReader(reader, int64(expectedSize)+1))
	if err != nil {
		return err
	}
	if written < 0 || uint64(written) != expectedSize { // #nosec G115 -- negativity is rejected before conversion.
		return errors.New("inflated size mismatch")
	}
	return nil
}

type objectResolver struct {
	objects     []packedObject
	byOffset    map[int]int
	bySHA       map[string]int
	resolved    map[int]resolvedObject
	resolving   map[int]bool
	readBase    BaseObjectReader
	externalSHA map[string]resolvedObject
}

func (r *objectResolver) resolve(index int) (resolvedObject, bool, error) {
	if resolved, ok := r.resolved[index]; ok {
		return resolved, true, nil
	}
	if r.resolving[index] {
		return resolvedObject{}, false, errors.New("packfile: delta cycle")
	}
	r.resolving[index] = true
	defer delete(r.resolving, index)
	object := r.objects[index]
	if isWholeObject(object.objectType) {
		return r.resolveWhole(index, object)
	}
	return r.resolveDelta(index, object)
}

func (r *objectResolver) resolveWhole(index int, object packedObject) (resolvedObject, bool, error) {
	if object.data == nil {
		return resolvedObject{}, false, nil
	}
	resolved := resolvedObject{
		objectType: object.objectType,
		data:       object.data,
		sha:        hashObject(object.objectType, object.data),
	}
	r.resolved[index] = resolved
	r.bySHA[resolved.sha] = index
	return resolved, true, nil
}

func (r *objectResolver) resolveDelta(index int, object packedObject) (resolvedObject, bool, error) {
	base, ok, err := r.resolveBase(object)
	if err != nil || !ok {
		return resolvedObject{}, ok, err
	}
	data, err := applyGitDelta(base.data, object.data)
	if err != nil {
		return resolvedObject{}, false, err
	}
	resolved := resolvedObject{
		objectType: base.objectType,
		data:       data,
		sha:        hashObject(base.objectType, data),
	}
	r.resolved[index] = resolved
	r.bySHA[resolved.sha] = index
	return resolved, true, nil
}

func (r *objectResolver) resolveBase(object packedObject) (resolvedObject, bool, error) {
	if object.objectType == packObjectOFSDelta {
		return r.resolveOffsetBase(object.baseOffset)
	}
	if cached, ok := r.externalSHA[object.baseSHA]; ok {
		return cached, true, nil
	}
	if index, ok := r.bySHA[object.baseSHA]; ok {
		return r.resolve(index)
	}
	if r.readBase == nil {
		return resolvedObject{}, false, nil
	}
	return r.resolveExternalBase(object.baseSHA)
}

func (r *objectResolver) resolveExternalBase(baseSHA string) (resolvedObject, bool, error) {
	base, ok, err := r.readBase(baseSHA)
	if err != nil || !ok {
		return resolvedObject{}, ok, err
	}
	objectType, ok := objectTypeCode(base.Type)
	if !ok {
		return resolvedObject{}, false, nil
	}
	resolved := resolvedObject{objectType: objectType, data: base.Data, sha: base.SHA}
	r.externalSHA[baseSHA] = resolved
	return resolved, true, nil
}

func (r *objectResolver) resolveOffsetBase(baseOffset int) (resolvedObject, bool, error) {
	index, ok := r.byOffset[baseOffset]
	if !ok {
		return resolvedObject{}, false, nil
	}
	return r.resolve(index)
}

func isWholeObject(objectType int) bool {
	return objectType == packObjectCommit || objectType == packObjectTree || objectType == packObjectBlob || objectType == packObjectTag
}

func isCommitOrTag(objectType int) bool {
	return objectType == packObjectCommit || objectType == packObjectTag
}

func objectTypeName(objectType int) string {
	switch objectType {
	case packObjectCommit:
		return "commit"
	case packObjectTree:
		return "tree"
	case packObjectBlob:
		return "blob"
	case packObjectTag:
		return "tag"
	default:
		return ""
	}
}

func objectTypeCode(name string) (int, bool) {
	switch name {
	case "commit":
		return packObjectCommit, true
	case "tree":
		return packObjectTree, true
	case "blob":
		return packObjectBlob, true
	case "tag":
		return packObjectTag, true
	default:
		return 0, false
	}
}

func hashObject(objectType int, data []byte) string {
	header := fmt.Sprintf("%s %d\x00", objectTypeName(objectType), len(data))
	hash := sha1.New() // #nosec G401 -- Git object IDs use SHA-1 by protocol definition.
	hash.Write([]byte(header))
	hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil))
}

func applyGitDelta(base, delta []byte) ([]byte, error) {
	baseSize, resultSize, pos, err := readDeltaHeader(delta)
	if err != nil {
		return nil, err
	}
	if baseSize != len(base) {
		return nil, errors.New("packfile: delta base size mismatch")
	}
	if resultSize > maxStoredPackObjectBytes {
		return nil, fmt.Errorf("packfile: delta result exceeds %d bytes", maxStoredPackObjectBytes)
	}
	result := make([]byte, 0, resultSize)
	for pos < len(delta) {
		instruction := delta[pos]
		pos++
		var err error
		result, pos, err = applyDeltaInstruction(result, base, delta, pos, instruction, resultSize)
		if err != nil {
			return nil, err
		}
	}
	if len(result) != resultSize {
		return nil, errors.New("packfile: delta result size mismatch")
	}
	return result, nil
}

func readDeltaHeader(delta []byte) (baseSize, resultSize, next int, err error) {
	baseSize, next, err = readDeltaSize(delta, 0)
	if err != nil {
		return 0, 0, 0, err
	}
	resultSize, next, err = readDeltaSize(delta, next)
	if err != nil {
		return 0, 0, 0, err
	}
	return baseSize, resultSize, next, nil
}

func applyDeltaInstruction(result, base, delta []byte, pos int, instruction byte, limit int) ([]byte, int, error) {
	if instruction&0x80 != 0 {
		return applyDeltaCopy(result, base, delta, pos, instruction, limit)
	}
	return applyDeltaInsert(result, delta, pos, instruction, limit)
}

func applyDeltaCopy(result, base, delta []byte, pos int, instruction byte, limit int) ([]byte, int, error) {
	offset, size, read, err := readCopyInstruction(delta[pos:], instruction)
	if err != nil {
		return nil, 0, err
	}
	pos += read
	if offset+size > len(base) {
		return nil, 0, errors.New("packfile: delta copy exceeds base")
	}
	if len(result)+size > limit {
		return nil, 0, errors.New("packfile: delta result exceeds declared size")
	}
	return append(result, base[offset:offset+size]...), pos, nil
}

func applyDeltaInsert(result, delta []byte, pos int, instruction byte, limit int) ([]byte, int, error) {
	if instruction == 0 {
		return nil, 0, errors.New("packfile: invalid delta instruction")
	}
	size := int(instruction)
	if pos+size > len(delta) {
		return nil, 0, errors.New("packfile: truncated delta insert")
	}
	if len(result)+size > limit {
		return nil, 0, errors.New("packfile: delta result exceeds declared size")
	}
	return append(result, delta[pos:pos+size]...), pos + size, nil
}

func readDeltaSize(delta []byte, pos int) (int, int, error) {
	shift := uint(0)
	size := uint64(0)
	for {
		if pos >= len(delta) {
			return 0, 0, errors.New("packfile: truncated delta size")
		}
		c := delta[pos]
		pos++
		if shift >= 64 {
			return 0, 0, errors.New("packfile: delta size exceeds limit")
		}
		size |= uint64(c&0x7f) << shift
		if size > maxStoredPackObjectBytes {
			return 0, 0, errors.New("packfile: delta size exceeds limit")
		}
		if c&0x80 == 0 {
			return int(size), pos, nil
		}
		shift += 7
	}
}

func readCopyInstruction(data []byte, instruction byte) (offset, size, read int, err error) {
	shift := uint(0)
	for bit := byte(0x01); bit <= 0x08; bit <<= 1 {
		if instruction&bit != 0 {
			if read >= len(data) {
				return 0, 0, 0, errors.New("packfile: truncated delta copy offset")
			}
			offset |= int(data[read]) << shift
			read++
		}
		shift += 8
	}
	shift = 0
	for bit := byte(0x10); bit <= 0x40; bit <<= 1 {
		if instruction&bit != 0 {
			if read >= len(data) {
				return 0, 0, 0, errors.New("packfile: truncated delta copy size")
			}
			size |= int(data[read]) << shift
			read++
		}
		shift += 8
	}
	if size == 0 {
		size = 0x10000
	}
	return offset, size, read, nil
}
