//go:build darwin

package doctor

import "testing"

func TestDarwinACLParserAndMatcher(t *testing.T) {
	entries, state := parseDarwinACLEntries("-rw-------@ 1 owner staff 0 Jan 1 00:00 token\n 0: group:everyone allow read\n")
	if state != ACLAbsent || len(entries) != 1 {
		t.Fatalf("parse entries = %+v, %v; want one entry", entries, state)
	}
	if entries[0].principal != "group:everyone" || entries[0].action != "allow" || len(entries[0].perms) != 1 || entries[0].perms[0] != "read" {
		t.Fatalf("entry = %+v, want parsed everyone allow read", entries[0])
	}

	identity := Identity{User: "agent", UID: 501, GID: 20, GroupIDs: []int{20}, GroupNames: []string{"staff"}}
	file := UnixFile{UID: 502, GID: 20}
	if got := darwinACLEntriesState(identity, file, entries, ACLFileEntry); got != ACLPresent {
		t.Fatalf("file read state = %v, want present", got)
	}
	if got := darwinACLEntriesState(identity, file, entries, ACLParentDirectory); got != ACLAbsent {
		t.Fatalf("parent read state = %v, want absent", got)
	}

	deny := []darwinACLEntry{{principal: "group:everyone", action: "deny", perms: []string{"read"}}}
	if got := darwinACLEntriesState(identity, file, deny, ACLFileEntry); got != ACLAbsent {
		t.Fatalf("deny state = %v, want absent", got)
	}
	unrelated := []darwinACLEntry{{principal: "user:someoneelse", action: "allow", perms: []string{"read"}}}
	if got := darwinACLEntriesState(identity, file, unrelated, ACLFileEntry); got != ACLAbsent {
		t.Fatalf("unrelated state = %v, want absent", got)
	}
	groupWrite := []darwinACLEntry{{principal: "group:staff", action: "allow", perms: []string{"write"}}}
	if got := darwinACLEntriesState(identity, file, groupWrite, ACLFileEntry); got != ACLPresent {
		t.Fatalf("group write state = %v, want present", got)
	}
	unknown := []darwinACLEntry{{principal: "ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C", action: "allow", perms: []string{"read"}}}
	if got := darwinACLEntriesState(identity, file, unknown, ACLFileEntry); got != ACLUnknown {
		t.Fatalf("unknown principal state = %v, want unknown", got)
	}
	if got := darwinACLEntriesState(identity, file, entries, ACLSocketEntry); got != ACLAbsent {
		t.Fatalf("socket read state = %v, want absent", got)
	}
	if _, malformed := parseDarwinACLEntries("-rw-------@ 1 owner staff 0 Jan 1 00:00 token\n inherited mystery\n"); malformed != ACLUnknown {
		t.Fatalf("malformed state = %v, want unknown", malformed)
	}
}
