// `postq policies {list,get,create,update,enable,disable,delete}` —
// org-level policy rules enforced by POST /v1/sign.
package commands

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/postqdev/postq-cli/internal/hybridsign"
	"github.com/postqdev/postq-cli/internal/ui"
)

func runPolicies(args []string, build BuildInfo) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printPoliciesHelp()
		return nil
	}
	switch args[0] {
	case "list", "ls":
		return runPoliciesList(args[1:], build)
	case "get", "show":
		return runPoliciesGet(args[1:], build)
	case "create":
		return runPoliciesCreate(args[1:], build)
	case "update":
		return runPoliciesUpdate(args[1:], build)
	case "enable":
		return runPoliciesToggle(args[1:], build, true)
	case "disable":
		return runPoliciesToggle(args[1:], build, false)
	case "delete", "rm":
		return runPoliciesDelete(args[1:], build)
	default:
		printPoliciesHelp()
		return fmt.Errorf("unknown policies subcommand: %s", args[0])
	}
}

func printPoliciesHelp() {
	fmt.Println(ui.Bold("postq policies") + " — org-level signing policies")
	fmt.Println()
	fmt.Println(ui.Bold("SUBCOMMANDS"))
	fmt.Println("  list                                       List all policies")
	fmt.Println("  get <id>                                   Show one policy")
	fmt.Println("  create --name N --rule @rule.json [...]   Create a new policy")
	fmt.Println("  update <id> [--name] [--rule] [--desc]    Update a policy")
	fmt.Println("  enable <id>                                Enable a policy")
	fmt.Println("  disable <id>                               Disable a policy")
	fmt.Println("  delete <id>                                Delete a policy")
	fmt.Println()
	fmt.Println(ui.Bold("RULE SHAPE (JSON)"))
	fmt.Println(`  {
    "operations": ["sign"],
    "action": "deny",
    "algorithms": ["mldsa44+ed25519"],
    "maxPayloadBytes": 1048576,
    "message": "ML-DSA-44 is too small for production"
  }`)
}

func runPoliciesList(args []string, build BuildInfo) error {
	fs := flag.NewFlagSet("policies list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "Machine-readable JSON output")
	apiKey := fs.String("api-key", "", "Override saved API key")
	endpoint := fs.String("api-endpoint", "", "Override saved API endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cl, err := newHybridClient(*endpoint, *apiKey, build)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	policies, err := cl.ListPolicies(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return jsonStdout(policies)
	}
	if len(policies) == 0 {
		fmt.Println(ui.Dim("No policies."))
		return nil
	}
	fmt.Printf("%s  %s  %s  %s\n",
		ui.Dim(pad("ID", 38)),
		ui.Dim(pad("STATE", 8)),
		ui.Dim(pad("ACTION", 18)),
		ui.Dim("NAME"),
	)
	for _, p := range policies {
		state := ui.Green("enabled")
		if !p.Enabled {
			state = ui.Yellow("disabled")
		}
		fmt.Printf("%s  %s  %s  %s\n",
			pad(p.ID, 38), pad(state, 8), pad(p.Rule.Action, 18), p.Name)
	}
	return nil
}

func runPoliciesGet(args []string, build BuildInfo) error {
	fs := flag.NewFlagSet("policies get", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "JSON output")
	apiKey := fs.String("api-key", "", "Override saved API key")
	endpoint := fs.String("api-endpoint", "", "Override saved API endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return fmt.Errorf("usage: postq policies get <id>")
	}
	cl, err := newHybridClient(*endpoint, *apiKey, build)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	p, err := cl.GetPolicy(ctx, rest[0])
	if err != nil {
		return err
	}
	if *asJSON {
		return jsonStdout(p)
	}
	printPolicy(*p)
	return nil
}

func printPolicy(p hybridsign.Policy) {
	fmt.Printf("id:          %s\n", p.ID)
	fmt.Printf("name:        %s\n", p.Name)
	if p.Description != nil {
		fmt.Printf("description: %s\n", *p.Description)
	}
	fmt.Printf("enabled:     %t\n", p.Enabled)
	fmt.Printf("created:     %s\n", p.CreatedAt)
	fmt.Printf("updated:     %s\n", p.UpdatedAt)
	fmt.Println("rule:")
	enc, _ := json.MarshalIndent(p.Rule, "  ", "  ")
	fmt.Println("  " + string(enc))
}

func runPoliciesCreate(args []string, build BuildInfo) error {
	fs := flag.NewFlagSet("policies create", flag.ContinueOnError)
	name := fs.String("name", "", "Policy name (required)")
	desc := fs.String("description", "", "Optional description")
	disabled := fs.Bool("disabled", false, "Create the policy in disabled state")
	rule := fs.String("rule", "", "Rule JSON object, or @path/to/rule.json (required)")
	asJSON := fs.Bool("json", false, "JSON output")
	apiKey := fs.String("api-key", "", "Override saved API key")
	endpoint := fs.String("api-endpoint", "", "Override saved API endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("--name is required")
	}
	if *rule == "" {
		return fmt.Errorf("--rule is required (JSON or @file)")
	}
	parsedRule, err := loadJSONFlag(*rule)
	if err != nil {
		return fmt.Errorf("--rule: %w", err)
	}
	body := map[string]any{
		"name":    *name,
		"enabled": !*disabled,
		"rule":    parsedRule,
	}
	if *desc != "" {
		body["description"] = *desc
	}
	cl, err := newHybridClient(*endpoint, *apiKey, build)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	p, err := cl.CreatePolicy(ctx, body)
	if err != nil {
		return err
	}
	if *asJSON {
		return jsonStdout(p)
	}
	fmt.Printf("%s created policy %s (%s)\n", ui.Green("✓"), p.Name, p.ID)
	return nil
}

func runPoliciesUpdate(args []string, build BuildInfo) error {
	fs := flag.NewFlagSet("policies update", flag.ContinueOnError)
	name := fs.String("name", "", "New name")
	desc := fs.String("description", "", "New description")
	rule := fs.String("rule", "", "New rule JSON or @file")
	asJSON := fs.Bool("json", false, "JSON output")
	apiKey := fs.String("api-key", "", "Override saved API key")
	endpoint := fs.String("api-endpoint", "", "Override saved API endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return fmt.Errorf("usage: postq policies update <id> [flags]")
	}
	body := map[string]any{}
	if *name != "" {
		body["name"] = *name
	}
	if *desc != "" {
		body["description"] = *desc
	}
	if *rule != "" {
		parsedRule, err := loadJSONFlag(*rule)
		if err != nil {
			return fmt.Errorf("--rule: %w", err)
		}
		body["rule"] = parsedRule
	}
	if len(body) == 0 {
		return fmt.Errorf("nothing to update — supply at least one of --name / --description / --rule")
	}
	cl, err := newHybridClient(*endpoint, *apiKey, build)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	p, err := cl.UpdatePolicy(ctx, rest[0], body)
	if err != nil {
		return err
	}
	if *asJSON {
		return jsonStdout(p)
	}
	fmt.Printf("%s updated policy %s\n", ui.Green("✓"), p.ID)
	return nil
}

func runPoliciesToggle(args []string, build BuildInfo, enabled bool) error {
	fs := flag.NewFlagSet("policies toggle", flag.ContinueOnError)
	apiKey := fs.String("api-key", "", "Override saved API key")
	endpoint := fs.String("api-endpoint", "", "Override saved API endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return fmt.Errorf("usage: postq policies %s <id>", map[bool]string{true: "enable", false: "disable"}[enabled])
	}
	cl, err := newHybridClient(*endpoint, *apiKey, build)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := cl.UpdatePolicy(ctx, rest[0], map[string]any{"enabled": enabled}); err != nil {
		return err
	}
	verb := "enabled"
	if !enabled {
		verb = "disabled"
	}
	fmt.Printf("%s %s policy %s\n", ui.Green("✓"), verb, rest[0])
	return nil
}

func runPoliciesDelete(args []string, build BuildInfo) error {
	fs := flag.NewFlagSet("policies delete", flag.ContinueOnError)
	apiKey := fs.String("api-key", "", "Override saved API key")
	endpoint := fs.String("api-endpoint", "", "Override saved API endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return fmt.Errorf("usage: postq policies delete <id>")
	}
	cl, err := newHybridClient(*endpoint, *apiKey, build)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := cl.DeletePolicy(ctx, rest[0]); err != nil {
		return err
	}
	fmt.Printf("%s deleted policy %s\n", ui.Green("✓"), rest[0])
	return nil
}

// loadJSONFlag parses a flag that's either a literal JSON object or @file.
func loadJSONFlag(s string) (map[string]any, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "@") {
		raw, err := os.ReadFile(strings.TrimPrefix(s, "@"))
		if err != nil {
			return nil, err
		}
		s = string(raw)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}
	return out, nil
}
