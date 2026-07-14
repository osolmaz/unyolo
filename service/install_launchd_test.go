package service

import (
	"testing"
)

func TestLaunchdInstallPlanValidate(t *testing.T) {
	plan := launchdInstallFixture()
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestLaunchdInstallPlanRejectsUnsafeValues(t *testing.T) {
	mutations := []func(*LaunchdInstallPlan){
		func(plan *LaunchdInstallPlan) { plan.PlistName = "other.plist" },
		func(plan *LaunchdInstallPlan) { plan.StateDir = plan.ConfigDir + "/state" },
		func(plan *LaunchdInstallPlan) { plan.Unit.UserName = "other" },
		func(plan *LaunchdInstallPlan) { plan.AdditionalGroups = []string{plan.Group} },
		func(plan *LaunchdInstallPlan) { plan.GroupMembers = map[string][]string{"unmanaged": {"bob"}} },
		func(plan *LaunchdInstallPlan) { plan.Files[0].Name = "../secret" },
		func(plan *LaunchdInstallPlan) { plan.Files[0].Mode = 0o666 },
		func(plan *LaunchdInstallPlan) {
			plan.RemoveFiles = []ManagedFileRef{{Area: ManagedFileConfig, Name: plan.Files[0].Name}}
		},
		func(plan *LaunchdInstallPlan) { plan.NoStart = false; plan.AllowNonRoot = true },
		func(plan *LaunchdInstallPlan) {
			plan.RuntimeDirectories = []LaunchdDirectory{{Path: "relative", Owner: "root", Group: "broker", Mode: 0o750}}
		},
	}
	for _, mutate := range mutations {
		plan := launchdInstallFixture()
		plan.Files = append([]ManagedFile(nil), plan.Files...)
		mutate(&plan)
		if err := plan.Validate(); err == nil {
			t.Fatalf("LaunchdInstallPlan.Validate(%+v) error = nil", plan)
		}
	}
}

func launchdInstallFixture() LaunchdInstallPlan {
	return LaunchdInstallPlan{
		User: "_broker", Group: "_broker", AdditionalGroups: []string{"broker-agent", "broker-operator"},
		GroupMembers: map[string][]string{"broker-agent": {"bob"}, "broker-operator": {"onur"}},
		ConfigDir:    "/Library/Application Support/BrokerKit/test", StateDir: "/Library/Application Support/BrokerKit/test-state",
		LaunchdDir: "/Library/LaunchDaemons", PlistName: "dev.brokerkit.test.plist", NoStart: true, AllowNonRoot: true,
		Files:              []ManagedFile{{Area: ManagedFileConfig, Name: "secret", Data: []byte("secret"), Mode: 0o600, Owner: ManagedFileOwnerService}},
		RuntimeDirectories: []LaunchdDirectory{{Path: "/var/run/brokerkit/test", Owner: "root", Group: "_broker", Mode: 0o750}},
		Unit: LaunchdUnit{Label: "dev.brokerkit.test", ProgramArguments: []string{"/usr/local/bin/test", "serve"}, UserName: "_broker", GroupName: "_broker",
			Sockets: []LaunchdSocket{{Name: "agent", Path: "/var/run/brokerkit/test/agent.sock", Owner: "root", Group: "broker-agent", Mode: 0o660, DirectoryMode: 0o750}}},
	}
}
