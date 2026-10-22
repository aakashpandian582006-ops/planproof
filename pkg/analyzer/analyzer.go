package analyzer

import (
	"encoding/json"
	"fmt"

	"planproof/pkg/config"
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
	GateStatus     string            `json:"gate_status"`
	RiskScore      int               `json:"risk_score"`
	Threshold      int               `json:"threshold"`
	Violations     []string          `json:"violations"`
	Remediations   []string          `json:"remediations"`
	TotalChanges   int               `json:"total_changes"`
	RuleViolations []rules.Violation `json:"rule_violations"`
	Summary        SeveritySummary   `json:"summary"`
	PolicyName     string            `json:"policy_name,omitempty"`
	PolicyVersion  string            `json:"policy_version,omitempty"`
}

// AnalyzePlan analyzes plan data using default baseline policy configuration.
func AnalyzePlan(planData []byte) (*RiskReport, error) {
	return AnalyzePlanWithPolicy(planData, config.DefaultConfig())
}

// AnalyzePlanWithThreshold analyzes plan data using a custom risk threshold.
func AnalyzePlanWithThreshold(planData []byte, threshold int) (*RiskReport, error) {
	cfg := config.DefaultConfig()
	if threshold > 0 {
		cfg.Gate.Threshold = threshold
	}
	return AnalyzePlanWithPolicy(planData, cfg)
}

// AnalyzePlanWithPolicy analyzes plan data using a comprehensive PolicyConfig.
func AnalyzePlanWithPolicy(planData []byte, cfg *config.PolicyConfig) (*RiskReport, error) {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	var plan TerraformPlan
	if err := json.Unmarshal(planData, &plan); err != nil {
		return nil, fmt.Errorf("failed to parse terraform json plan: %w", err)
	}

	report := &RiskReport{
		IsUnsafe:       false,
		GateStatus:     "PASSED",
		RiskScore:      0,
		Threshold:      cfg.Gate.Threshold,
		Violations:     []string{},
		Remediations:   []string{},
		TotalChanges:   len(plan.ResourceChanges),
		RuleViolations: []rules.Violation{},
		Summary:        SeveritySummary{},
		PolicyName:     cfg.Name,
		PolicyVersion:  cfg.Version,
	}

	engine := rules.NewRuleEngine()
	rawViolations := engine.Evaluate(plan.ResourceChanges)

	for _, v := range rawViolations {
		// Filter out disabled rules according to policy
		if !cfg.IsRuleEnabled(v.RuleID) {
			continue
		}

		// Apply severity and risk score overrides from policy
		v.Severity = rules.Severity(cfg.GetRuleSeverity(v.RuleID, string(v.Severity)))
		v.RiskScore = cfg.GetRuleRiskScore(v.RuleID, string(v.Severity), v.RiskScore)

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

	// Gate fails if calculated risk score meets/exceeds threshold or critical/high policy triggers fire
	if report.RiskScore >= cfg.Gate.Threshold ||
		(cfg.Gate.FailOnCritical && report.Summary.Critical > 0) ||
		(cfg.Gate.FailOnHigh && report.Summary.High > 0) {
		report.IsUnsafe = true
		report.GateStatus = "FAILED"
	}

	return report, nil
}
