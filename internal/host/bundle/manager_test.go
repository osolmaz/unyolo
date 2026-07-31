package bundle

import "testing"

func TestLaunchdPlistPath(t *testing.T) {
	t.Parallel()
	if got := launchdPlistPath("io.unyolo.github"); got != "/Library/LaunchDaemons/io.unyolo.github.plist" {
		t.Fatalf("launchdPlistPath() = %q", got)
	}
}

func TestLaunchdSystemTarget(t *testing.T) {
	t.Parallel()
	if got := launchdSystemTarget("io.unyolo.github"); got != "system/io.unyolo.github" {
		t.Fatalf("launchdSystemTarget() = %q", got)
	}
}

func TestLaunchdParsePID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		body string
		want int
	}{
		{"pid = 42\n", 42},
		{"state = running\n", 0},
		{"pid = notanumber\n", 0},
		{"", 0},
	}
	for _, testcase := range cases {
		if got := launchdParsePID(testcase.body); got != testcase.want {
			t.Fatalf("launchdParsePID(%q) = %d, want %d", testcase.body, got, testcase.want)
		}
	}
}
