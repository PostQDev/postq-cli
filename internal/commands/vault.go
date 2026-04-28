// `postq vault settings {show,put,clear}` — manage per-org BYOK / KMS
// settings. The encrypted secret is never returned in plaintext.
package commands

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/postqdev/postq-cli/internal/ui"
)

func runVault(args []string, build BuildInfo) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printVaultHelp()
		return nil
	}
	switch args[0] {
	case "settings":
		return runVaultSettings(args[1:], build)
	default:
		printVaultHelp()
		return fmt.Errorf("unknown vault subcommand: %s", args[0])
	}
}

func printVaultHelp() {
	fmt.Println(ui.Bold("postq vault") + " — per-org KMS / BYOK configuration")
	fmt.Println()
	fmt.Println(ui.Bold("SUBCOMMANDS"))
	fmt.Println("  settings show                                           Show current vault settings")
	fmt.Println("  settings put --provider env|aws-kms|azure-kv [...]      Configure or update KMS")
	fmt.Println("  settings clear                                          Revert to env-managed KEK")
	fmt.Println()
	fmt.Println(ui.Bold("FLAGS for `settings put`"))
	fmt.Println("  --provider env|aws-kms|azure-kv   Required")
	fmt.Println("  --aws-region REGION               (aws-kms) AWS region")
	fmt.Println("  --aws-key-arn ARN                 (aws-kms) KMS key ARN")
	fmt.Println("  --azure-vault URL                 (azure-kv) Vault URL")
	fmt.Println("  --azure-key NAME                  (azure-kv) Key name")
}

func runVaultSettings(args []string, build BuildInfo) error {
	if len(args) == 0 {
		printVaultHelp()
		return nil
	}
	switch args[0] {
	case "show", "get":
		return runVaultSettingsShow(args[1:], build)
	case "put", "set":
		return runVaultSettingsPut(args[1:], build)
	case "clear", "delete", "rm":
		return runVaultSettingsClear(args[1:], build)
	default:
		printVaultHelp()
		return fmt.Errorf("unknown settings action: %s", args[0])
	}
}

func runVaultSettingsShow(args []string, build BuildInfo) error {
	fs := flag.NewFlagSet("vault settings show", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "JSON output")
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
	s, err := cl.GetVaultSettings(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return jsonStdout(s)
	}
	if s == nil {
		fmt.Println(ui.Dim("No vault settings configured (using env-managed KEK)."))
		return nil
	}
	fmt.Printf("kek provider:  %s\n", s.KekProvider)
	if s.ConfiguredAt != nil {
		fmt.Printf("configured:    %s\n", *s.ConfiguredAt)
	}
	if s.UpdatedAt != nil {
		fmt.Printf("updated:       %s\n", *s.UpdatedAt)
	}
	if s.Aws != nil {
		fmt.Println("aws:")
		for k, v := range s.Aws {
			fmt.Printf("  %s: %v\n", k, v)
		}
	}
	if s.Azure != nil {
		fmt.Println("azure:")
		for k, v := range s.Azure {
			fmt.Printf("  %s: %v\n", k, v)
		}
	}
	return nil
}

func runVaultSettingsPut(args []string, build BuildInfo) error {
	fs := flag.NewFlagSet("vault settings put", flag.ContinueOnError)
	provider := fs.String("provider", "", "KEK provider: env | aws-kms | azure-kv (required)")
	awsRegion := fs.String("aws-region", "", "(aws-kms) AWS region")
	awsKeyArn := fs.String("aws-key-arn", "", "(aws-kms) KMS key ARN")
	azureVault := fs.String("azure-vault", "", "(azure-kv) Key Vault URL")
	azureKey := fs.String("azure-key", "", "(azure-kv) key name")
	asJSON := fs.Bool("json", false, "JSON output")
	apiKey := fs.String("api-key", "", "Override saved API key")
	endpoint := fs.String("api-endpoint", "", "Override saved API endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *provider == "" {
		return fmt.Errorf("--provider is required (env | aws-kms | azure-kv)")
	}
	body := map[string]any{"kekProvider": *provider}
	switch *provider {
	case "aws-kms":
		if *awsRegion == "" || *awsKeyArn == "" {
			return fmt.Errorf("aws-kms requires --aws-region and --aws-key-arn")
		}
		body["aws"] = map[string]any{
			"region": *awsRegion,
			"keyArn": *awsKeyArn,
		}
	case "azure-kv":
		if *azureVault == "" || *azureKey == "" {
			return fmt.Errorf("azure-kv requires --azure-vault and --azure-key")
		}
		body["azure"] = map[string]any{
			"vaultUrl": *azureVault,
			"keyName":  *azureKey,
		}
	case "env":
		// Nothing extra.
	default:
		return fmt.Errorf("unknown --provider %q", *provider)
	}

	cl, err := newHybridClient(*endpoint, *apiKey, build)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s, err := cl.PutVaultSettings(ctx, body)
	if err != nil {
		return err
	}
	if *asJSON {
		return jsonStdout(s)
	}
	fmt.Printf("%s configured vault: kekProvider=%s\n", ui.Green("✓"), s.KekProvider)
	return nil
}

func runVaultSettingsClear(args []string, build BuildInfo) error {
	fs := flag.NewFlagSet("vault settings clear", flag.ContinueOnError)
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
	if err := cl.ClearVaultSettings(ctx); err != nil {
		return err
	}
	fmt.Printf("%s cleared vault settings (reverted to env-managed KEK)\n", ui.Green("✓"))
	return nil
}
