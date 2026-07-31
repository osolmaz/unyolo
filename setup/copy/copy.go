// Package copy contains the normal guided-installer wording.
package copy

const (
	Title = "Set up unYOLO"
	Intro = "Choose what you want to set up. You can review every change before it is applied."
)

type Goal struct {
	Value string
	Label string
	Hint  string
}

var Goals = []Goal{
	{Value: "complete_local", Label: "Set up this computer", Hint: "Install credential services and connect an agent"},
	{Value: "credential_service", Label: "Install credential services", Hint: "Keep credentials here and connect an agent later"},
	{Value: "agent_connection", Label: "Connect an agent", Hint: "Use credential services that are already running"},
	{Value: "command_only", Label: "Install the unYOLO command", Hint: "Make no administrator changes"},
}

var ForbiddenNormalTerms = []string{
	"deployment kit", "deployment pack", "materialize", "operator", "protected worker", "runtime bundle",
}
