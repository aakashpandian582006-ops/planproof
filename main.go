package main

import (
	"flag"
	"fmt"
	"os"

	"planproof/pkg/analyzer"
)

func main() {
	planFlag := flag.String("plan", "", "Path to Terraform Plan JSON file")
	thresholdFlag := flag.Int("threshold", 50, "Risk score threshold to halt deployment (default: 50)")
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

	planData, err := os.ReadFile(planPath)
	if err != nil {
		fmt.Printf("Error reading plan file '%s': %v\n", planPath, err)
		os.Exit(1)
	}

	report, err := analyzer.AnalyzePlanWithThreshold(planData, *thresholdFlag)
	if err != nil {
		fmt.Printf("Error analyzing plan: %v\n", err)
		os.Exit(1)
	}

	printReport(planPath, report)

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
