package doctor

import (
	"strings"
	"testing"
)

func TestParseProcessStatus(t *testing.T) {
	status, err := ParseProcessStatus([]byte("Uid:\t1001\t1002\t1003\t1004\nGid:\t2001\t2002\t2003\t2004\nGroups:\t3001 3002\nCapEff:\t0000000000200000\nCapPrm:\t0000000000000002\n"))
	if err != nil {
		t.Fatal(err)
	}
	if status.FilesystemUID != 1004 || status.FilesystemGID != 2004 || len(status.Groups) != 2 || status.EffectiveCaps != 1<<21 || status.PermittedCaps != 1<<1 {
		t.Fatalf("status = %+v", status)
	}
}

func TestParseProcessStatusErrors(t *testing.T) {
	for _, test := range []struct {
		body string
		want string
	}{
		{body: "Gid:\t1\n", want: "uid field is missing"},
		{body: "Uid:\t1\n", want: "gid field is missing"},
		{body: "Uid:\t\n", want: "uid field is empty"},
		{body: "Uid:\tbad\n", want: "parse uid"},
		{body: "CapEff:\tnope\n", want: "parse CapEff"},
	} {
		if _, err := ParseProcessStatus([]byte(test.body)); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("ParseProcessStatus(%q) error = %v, want %q", test.body, err, test.want)
		}
	}
}

func TestParseProcessStatusAllowsEmptyGroupsAndShortIDs(t *testing.T) {
	status, err := ParseProcessStatus([]byte("ignored\nUid:\t1\nGid:\t2\nGroups:\t\n"))
	if err != nil || status.FilesystemUID != 1 || status.FilesystemGID != 2 || len(status.Groups) != 0 {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

func TestProcessStatusUIDPredicates(t *testing.T) {
	status := ProcessStatus{UIDs: []int{42, 42, 42, 42}}
	if !status.AllUIDsMatch(42) || !status.HasUID(42) || status.HasUID(7) {
		t.Fatalf("unexpected UID predicates for %+v", status.UIDs)
	}
	if (ProcessStatus{}).AllUIDsMatch(42) {
		t.Fatal("empty UID set matched")
	}
	if (ProcessStatus{UIDs: []int{42, 7}}).AllUIDsMatch(42) {
		t.Fatal("mixed UID set matched")
	}
}

func TestRootEquivalentCapabilityNames(t *testing.T) {
	got := RootEquivalentCapabilityNames(1<<21, 1<<1)
	if len(got) != 2 || got[0] != "CAP_DAC_OVERRIDE" || got[1] != "CAP_SYS_ADMIN" {
		t.Fatalf("capabilities = %v", got)
	}
	if got := RootEquivalentCapabilityNames(0, 0); len(got) != 0 {
		t.Fatalf("empty capabilities = %v", got)
	}
}
