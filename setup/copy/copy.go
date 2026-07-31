// Package copy contains the normal guided-installer wording.
//
// It is the single source of truth for user-facing text used by
// the wizard state machine. Copy is keyed by screen ID so the state
// machine and its renderers reference the same strings.
package copy

const (
	Title = "Set up unYOLO"
	Intro = "Choose what you want to set up. You can review every change before it is applied."
)

// Screen groups the copy strings for one guided-setup step.
type Screen struct {
	// Question is the one direct question shown to the user.
	Question string
	// Reason is a single sentence explaining why the answer matters.
	Reason string
	// Primary is the label for the confirmed forward action, or empty when
	// the screen has no confirmation.
	Primary string
	// Secondary is the label for the cancel action.
	Secondary string
}

// Screen IDs. These are stable and appear in tests and transcripts.
const (
	ScreenGoal            = "goal"
	ScreenServiceLocation = "service_location"
	ScreenProviders       = "providers"
	ScreenAgentLocation   = "agent_location"
	ScreenAccount         = "account"
	ScreenIsolationWarn   = "isolation_warning"
	ScreenReview          = "review"
	ScreenInstallCommand  = "install_command"
	ScreenAdminChanges    = "administrator_changes"
	ScreenInstallName     = "installation_name"
	ScreenResumeChoice    = "resume_choice"
	ScreenDiscardProgress = "discard_progress"
)

// Screens is the closed set of screens referenced by the wizard state machine.
var Screens = map[string]Screen{
	ScreenGoal: {
		Question: "What do you want to set up?",
		Reason:   "The rest of the questions depend on this choice.",
	},
	ScreenServiceLocation: {
		Question: "Where should the credential services run?",
		Reason:   "Native services run outside Docker. Docker keeps every broker in its own container.",
	},
	ScreenProviders: {
		Question: "Which credentials should unYOLO protect?",
		Reason:   "Each option installs one credential service you can add or remove later.",
	},
	ScreenAgentLocation: {
		Question: "Where does the agent run?",
		Reason:   "The agent asks the credential services for provider access.",
	},
	ScreenAccount: {
		Question: "Which account should run the agent?",
		Reason:   "The agent connection uses this account's home directory and identity.",
	},
	ScreenIsolationWarn: {
		Question:  "Continue with reduced isolation?",
		Reason:    "The agent will share your account. It may access files your account can already read. It is never the recommended choice for a complete local setup.",
		Primary:   "Continue with reduced isolation",
		Secondary: "Choose another account",
	},
	ScreenReview: {
		Question: "Ready to set up unYOLO",
		Reason:   "Every change below is applied only after your confirmation.",
		Primary:  "Install",
	},
	ScreenInstallCommand: {
		Question:  "Install the unYOLO command?",
		Reason:    "This installs the verified command for your account. No system services are changed.",
		Primary:   "Install command",
		Secondary: "Cancel",
	},
	ScreenAdminChanges: {
		Question:  "Allow these administrator changes?",
		Reason:    "The verified administrator helper rejects a changed plan or changed host state.",
		Primary:   "Apply system changes",
		Secondary: "Cancel",
	},
	ScreenInstallName: {
		Question: "Name this installation",
		Reason:   "An installation with the name \"default\" already exists on this computer. Choose another name to keep both.",
	},
	ScreenResumeChoice: {
		Question:  "Continue the unfinished setup?",
		Reason:    "The saved answers contain no credentials.",
		Primary:   "Continue",
		Secondary: "Start over",
	},
	ScreenDiscardProgress: {
		Question:  "Saved setup progress cannot be opened. Discard it and start over?",
		Reason:    "This removes only unfinished answers. Installed services, credentials, and saved installations are not changed.",
		Primary:   "Discard and start over",
		Secondary: "Cancel",
	},
}

// Goal is one selectable overall setup goal.
type Goal struct {
	Value string
	Label string
	Hint  string
}

// Goals is the ordered list of goal choices, presented top-to-bottom.
var Goals = []Goal{
	{Value: "complete_local", Label: "Set up this computer", Hint: "Install credential services and connect an agent"},
	{Value: "credential_service", Label: "Install credential services", Hint: "Keep credentials here and connect an agent later"},
	{Value: "agent_connection", Label: "Connect an agent", Hint: "Use credential services that are already running"},
	{Value: "command_only", Label: "Install the unYOLO command", Hint: "Make no administrator changes"},
}

// Service is one selectable credential-service location.
type Service struct {
	Value string
	Label string
	Hint  string
}

// Services is the ordered list of credential-service locations.
var Services = []Service{
	{Value: "native", Label: "Run as background services on this computer", Hint: "Use the native service manager"},
	{Value: "docker", Label: "Run in Docker on this computer", Hint: "Use a Compose configuration with separate containers"},
}

// AgentLocation is one selectable agent placement.
type AgentLocation struct {
	Value string
	Label string
	Hint  string
}

// AgentLocations is the ordered list of agent placements.
var AgentLocations = []AgentLocation{
	{Value: "managed", Label: "A new separate account on this computer", Hint: "unYOLO creates a restricted account"},
	{Value: "existing", Label: "An existing account on this computer", Hint: "Connect an account that already exists"},
	{Value: "container", Label: "A Docker container on this computer", Hint: "Connect one Compose service"},
	{Value: "remote", Label: "Another computer", Hint: "Create a short-lived pairing invitation"},
	{Value: "current", Label: "My current account", Hint: "Less isolation: the agent may access files available to your account"},
}

// ForbiddenNormalTerms are internal deployment terms that must not appear in
// normal user-facing transcripts. Technical-details views may reference them
// after explaining their plain meaning.
var ForbiddenNormalTerms = []string{
	"deployment kit",
	"deployment pack",
	"materialize",
	"protected worker",
	"runtime bundle",
	"provider-owned enrollment profile",
	"credential slot",
	"plan digest",
	"operator",
}

// FooterHint is the persistent action hint rendered under menu and text
// screens so keyboard controls are always visible.
const FooterHint = "Enter continues · Choose ← Go back to return · Ctrl+C cancels"
