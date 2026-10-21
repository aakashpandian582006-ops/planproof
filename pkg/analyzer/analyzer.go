package analyzer

import (
	"encoding/json"
	"fmt"

	"planproof/pkg/rules"
)

// TerraformPlan defines the relevant schema of a Terraform plan in JSON format.
type TerraformPlan struct {
	FormatVersion    string                 `json:"format_version"`
	TerraformVersion string                 `json:"terraform_version"`
	ResourceChanges  []rules.ResourceChange `json:"resource_changes"`
}

// SeveritySummary aggregates violation counts by severity level.
type SeveritySummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// RiskReport captures the comprehensive risk evaluation of a plan.
type RiskReport struct {
	IsUnsafe       bool              `json:"is_unsafe"`
	RiskScore      int               `json:"risk_score"`
	Threshold      int               `json:"threshold"`
	Violations     []string          `json:"violations"`
	Remediations   []string          `json:"remediations"`
	TotalChanges   int               `json:"total_changes"`
	RuleViolations []rules.Violation `json:"rule_violations"`
	Summary        SeveritySummary   `json:"summary"`
}

// AnalyzePlan analyzes plan data using the default risk threshold of 50.
func AnalyzePlan(planData []byte) (*RiskReport, error) {
	return AnalyzePlanWithThreshold(planData, 50)
}

// AnalyzePlanWithThreshold analyzes plan data using a custom risk threshold.
func AnalyzePlanWithThreshold(planData []byte, threshold int) (*RiskReport, error) {
	if threshold <= 0 {
		threshold = 50
	}

	var plan TerraformPlan
	if err := json.Unmarshal(planData, &plan); err != nil {
		return nil, fmt.Errorf("failed to parse terraform json plan: %w", err)
	}

	report := &RiskReport{
		IsUnsafe:       false,
		RiskScore:      0,
		Threshold:      threshold,
		Violations:     []string{},
		Remediations:   []string{},
		TotalChanges:   len(plan.ResourceChanges),
		RuleViolations: []rules.Violation{},
		Summary:        SeveritySummary{},
	}

	engine := rules.NewRuleEngine()
	violations := engine.Evaluate(plan.ResourceChanges)

	for _, v := range violations {
		report.RuleViolations = append(report.RuleViolations, v)
		report.RiskScore += v.RiskScore

		// Format individual violation with clear severity tagging
		report.Violations = append(report.Violations,
			fmt.Sprintf("[%s] %s: %s", v.Severity, v.RuleID, v.Description))

		if v.Remediation != "" {
			report.Remediations = append(report.Remediations,
				fmt.Sprintf("[%s] %s: %s", v.Severity, v.RuleID, v.Remediation))
		}

		switch v.Severity {
		case rules.SeverityCritical:
			report.Summary.Critical++
		case rules.SeverityHigh:
			report.Summary.High++
		case rules.SeverityMedium:
			report.Summary.Medium++
		case rules.SeverityLow:
			report.Summary.Low++
		}
	}

	// Gate fails if calculated risk score meets/exceeds threshold or critical risks exist
	if report.RiskScore >= threshold || report.Summary.Critical > 0 {
		report.IsUnsafe = true
	}

	return report, nil
}
