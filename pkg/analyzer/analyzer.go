package analyzer

import (
	"encoding/json"
	"fmt"
)

type ResourceChange struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Change  struct {
		Actions []string `json:"actions"`
	} `json:"change"`
}

type TerraformPlan struct {
	FormatVersion    string           `json:"format_version"`
	TerraformVersion string           `json:"terraform_version"`
	ResourceChanges  []ResourceChange `json:"resource_changes"`
}

type RiskReport struct {
	IsUnsafe     bool     `json:"is_unsafe"`
	RiskScore    int      `json:"risk_score"`
	Violations   []string `json:"violations"`
	Remediations []string `json:"remediations"`
	TotalChanges int      `json:"total_changes"`
}

func AnalyzePlan(planData []byte) (*RiskReport, error) {
	var plan TerraformPlan
	if err := json.Unmarshal(planData, &plan); err != nil {
		return nil, fmt.Errorf("failed to parse terraform json plan: %w", err)
	}

	report := &RiskReport{
		IsUnsafe:     false,
		RiskScore:    0,
		Violations:   []string{},
		Remediations: []string{},
		TotalChanges: len(plan.ResourceChanges),
	}

	statefulTypes := map[string]bool{
		"aws_db_instance":            true,
		"aws_s3_bucket":              true,
		"azurerm_postgresql_server":  true,
		"google_sql_database_instance": true,
	}

	for _, rc := range plan.ResourceChanges {
		isDestructive := false
		for _, action := range rc.Change.Actions {
			if action == "destroy" || action == "delete" {
				isDestructive = true
				break
			}
		}

		if isDestructive && statefulTypes[rc.Type] {
			report.IsUnsafe = true
			report.RiskScore += 50
			report.Violations = append(report.Violations,
				fmt.Sprintf("CRITICAL RISK: Stateful resource '%s' (%s) is scheduled for DESTRUCTION without disaster recovery validation.", rc.Address, rc.Type))
			report.Remediations = append(report.Remediations,
				fmt.Sprintf("REMEDIATION: Add 'lifecycle { prevent_destroy = true }' to '%s' block or enable deletion protection.", rc.Address))
		}
	}

	return report, nil
}
