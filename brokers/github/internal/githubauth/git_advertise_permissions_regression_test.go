package githubauth

import "testing"

func TestGitReceivePackAdvertisementNeedsWrite(t *testing.T) {
	for _, tc := range []struct{ operation, want string }{
		{"git.fetch", "read"},
		{"git.push.advertise", "write"},
		{"git.push.branch_create", "write"},
		{"git.push.fast_forward", "write"},
	} {
		t.Run(tc.operation, func(t *testing.T) {
			got, err := permissionsForOperation(tc.operation)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got["contents"] != tc.want {
				t.Fatalf("%s credential permissions: got %v; want only contents:%s", tc.operation, got, tc.want)
			}
			fake, manager := newCompatGitHub(t, nil)
			if _, err := manager.RepositoryCredential(t.Context(), tc.operation, "acme", "one"); err != nil {
				t.Fatal(err)
			}
			minted := fake.minted["42"]
			if len(minted) != 2 || len(fake.minted) != 1 {
				t.Fatalf("mint requests = %v; want one bootstrap and one exact mint", fake.minted)
			}
			assertExactTokenRequest(t, minted[1], []int64{1}, map[string]string{"contents": tc.want})
			manager.InvalidateInstallation(42, true)
			if _, err := manager.RepositoryCredential(t.Context(), tc.operation, "acme", "one"); err == nil {
				t.Fatal("suspended installation minted a credential")
			}
			if len(fake.minted["42"]) != 2 {
				t.Fatal("suspended installation sent another mint request")
			}
		})
	}
}
