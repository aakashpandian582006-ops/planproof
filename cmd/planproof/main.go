package main

import (
	"fmt"
	"os"

	"planproof/pkg/analyzer"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: planproof <path-to-terraform-plan-json>")
		os.Exit(1)
	}

	filePath := os.Args[1]
	planData, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Error reading plan file: %v\n", err)
		os.Exit(1)
	}

	report, err := analyzer.AnalyzePlan(planData)
	if err != nil {
		fmt.Printf("Analysis error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("==================================================")
	fmt.Println("   PLANPROOF: TERRAFORM RISK GATE ANALYSIS REPORT")
	fmt.Println("==================================================")
	fmt.Printf("Total Resource Changes Evaluated: %d\n", report.TotalChanges)
	fmt.Printf("Calculated Risk Score:           %d\n", report.RiskScore)

	if report.IsUnsafe {
		fmt.Println("Status:                          [FAILED] UNACCEPTABLE RISK DETECTED")
		fmt.Println("--------------------------------------------------")
		fmt.Println("Violations Found:")
		for _, v := range report.Violations {
			fmt.Printf("  - %s\n", v)
		}
		fmt.Println("--------------------------------------------------")
		fmt.Println("Pipeline Action: Halting deployment to prevent stateful data loss.")
		os.Exit(1)
	} else {
		fmt.Println("Status:                          [PASSED] SAFE TO APPLY")
		fmt.Println("--------------------------------------------------")
		fmt.Println("No destructive stateful resource changes detected.")
		os.Exit(0)
	}
}
