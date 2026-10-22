package main

import (
	"flag"
	"fmt"
	"os"

	"planproof/pkg/analyzer"
	"planproof/pkg/config"
	"planproof/pkg/reporter"
)

func main() {
	planFlag := flag.String("plan", "", "Path to Terraform Plan JSON file")
	thresholdFlag := flag.Int("threshold", 50, "Risk score threshold to halt deployment (default: 50)")
	configFlag := flag.String("config", "", "Path to YAML policy config file (e.g. policy.yaml)")
	outputHTMLFlag := flag.String("output-html", "", "Path to export HTML security report (e.g. report.html)")
	outputJSONFlag := flag.String("output-json", "", "Path to export JSON security report (e.g. report.json)")
	flag.Parse()

	planPath := *planFlag
	if planPath == "" && flag.NArg() > 0 {
		planPath = flag.Arg(0)
	}

	if planPath == "" {
		fmt.Println("Usage: planproof [options] <path-to-terraform-plan-json>")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// 1. Resolve Policy Configuration
	var cfg *config.PolicyConfig
	var err error
	if *configFlag != "" {
		cfg, err = config.LoadConfig(*configFlag)
		if err != nil {
			fmt.Printf("Error loading config file '%s': %v\n", *configFlag, err)
			os.Exit(1)
		}
	} else if _, statErr := os.Stat("policy.yaml"); statErr == nil {
		// Automatically use default policy.yaml in current directory if present
		cfg, err = config.LoadConfig("policy.yaml")
		if err != nil {
			fmt.Printf("Warning: failed to parse local policy.yaml: %v. Using default baseline policy.\n", err)
			cfg = config.DefaultConfig()
		}
	} else {
		cfg = config.DefaultConfig()
	}

	// If -threshold was explicitly set on command line, override config
	thresholdExplicit := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "threshold" {
			thresholdExplicit = true
		}
	})
	if thresholdExplicit {
		cfg.Gate.Threshold = *thresholdFlag
	}

	// 2. Read Target Terraform Plan JSON
	planData, err := os.ReadFile(planPath)
	if err != nil {
		fmt.Printf("Error reading plan file '%s': %v\n", planPath, err)
		os.Exit(1)
	}

	// 3. Analyze Plan against Policy
	report, err := analyzer.AnalyzePlanWithPolicy(planData, cfg)
	if err != nil {
		fmt.Printf("Error analyzing plan: %v\n", err)
		os.Exit(1)
	}

	// 4. Print CLI Console Audit Report
	printReport(planPath, report)

	// 5. Build Report Export Payload
	reportData := reporter.BuildReportData(planPath, report)

	// 6. Optional JSON Export
	if *outputJSONFlag != "" {
		if err := reporter.ExportJSON(reportData, *outputJSONFlag); err != nil {
			fmt.Printf("Error generating JSON report: %v\n", err)
		} else {
			fmt.Printf("Structured JSON report generated: %s\n", *outputJSONFlag)
		}
	}

	// 7. Optional HTML Export
	if *outputHTMLFlag != "" {
		if err := reporter.ExportHTML(reportData, *outputHTMLFlag); err != nil {
			fmt.Printf("Error generating HTML report: %v\n", err)
		} else {
			fmt.Printf("Executive HTML security report generated: %s\n", *outputHTMLFlag)
		}
	}

	// 8. Pipeline Gate Decision
	if report.IsUnsafe {
		os.Exit(1)
	}
	os.Exit(0)
}

func printReport(planPath string, report *analyzer.RiskReport) {
	fmt.Println("================================================================================")
	fmt.Println("          PLANPROOF: ENTERPRISE IAC RISK GATE & SECURITY AUDITOR                ")
	fmt.Println("================================================================================")
	fmt.Printf("Target Plan File:                 %s\n", planPath)
	if report.PolicyName != "" {
		fmt.Printf("Active Policy:                    %s (v%s)\n", report.PolicyName, report.PolicyVersion)
	}
	fmt.Printf("Total Resource Changes Evaluated: %d\n", report.TotalChanges)
	fmt.Printf("Configured Risk Threshold:        %d\n", report.Threshold)
	fmt.Printf("Calculated Overall Risk Score:    %d\n", report.RiskScore)

	fmt.Println("\n--------------------------------------------------------------------------------")
	fmt.Println("RULE VIOLATION AUDIT BREAKDOWN")
	fmt.Println("--------------------------------------------------------------------------------")

	if len(report.RuleViolations) == 0 {
		fmt.Println("No security rule violations or destructive stateful changes detected.")
	} else {
		for _, v := range report.RuleViolations {
			fmt.Printf("[%s] %s - %s\n", v.Severity, v.RuleID, v.ResourceAddress)
			fmt.Printf("  Description: %s\n", v.Description)
			if v.Remediation != "" {
				fmt.Printf("  Remediation: %s\n", v.Remediation)
			}
			fmt.Printf("  Impact:      +%d risk points\n\n", v.RiskScore)
		}
	}

	fmt.Println("Severity Summary:")
	fmt.Printf("  - CRITICAL: %d\n", report.Summary.Critical)
	fmt.Printf("  - HIGH:     %d\n", report.Summary.High)
	fmt.Printf("  - MEDIUM:   %d\n", report.Summary.Medium)
	fmt.Printf("  - LOW:      %d\n", report.Summary.Low)

	fmt.Println("\n================================================================================")
	if report.IsUnsafe {
		fmt.Println("GATE STATUS: [FAILED] UNACCEPTABLE RISK DETECTED")
		fmt.Printf("Pipeline Action: Halting deployment. Risk score %d (threshold: %d) or Critical risks identified.\n", report.RiskScore, report.Threshold)
		fmt.Println("================================================================================")
	} else {
		fmt.Println("GATE STATUS: [PASSED] SAFE TO APPLY")
		fmt.Println("Pipeline Action: Deployment approved. All security and state-safety gates satisfied.")
		fmt.Println("================================================================================")
	}
}
