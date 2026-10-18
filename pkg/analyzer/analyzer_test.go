package analyzer

import (
	"testing"
)

func TestAnalyzePlan_Safe(t *testing.T) {
	safePlanJSON := []byte(`{
		"format_version": "1.2",
		"terraform_version": "1.5.0",
		"resource_changes": [
			{
				"address": "aws_instance.web",
				"type": "aws_instance",
				"name": "web",
				"change": {
					"actions": ["create"]
				}
			}
		]
	}`)

	report, err := AnalyzePlan(safePlanJSON)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if report.IsUnsafe {
		t.Errorf("Expected IsUnsafe to be false, got true")
	}

	if report.RiskScore != 0 {
		t.Errorf("Expected RiskScore to be 0, got %d", report.RiskScore)
	}

	if len(report.Violations) != 0 {
		t.Errorf("Expected 0 violations, got %d", len(report.Violations))
	}
}

func TestAnalyzePlan_Unsafe(t *testing.T) {
	unsafePlanJSON := []byte(`{
		"format_version": "1.2",
		"terraform_version": "1.5.0",
		"resource_changes": [
			{
				"address": "aws_db_instance.primary_postgres",
				"type": "aws_db_instance",
				"name": "primary_postgres",
				"change": {
					"actions": ["destroy"]
				}
			}
		]
	}`)

	report, err := AnalyzePlan(unsafePlanJSON)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !report.IsUnsafe {
		t.Errorf("Expected IsUnsafe to be true, got false")
	}

	if report.RiskScore < 50 {
		t.Errorf("Expected RiskScore >= 50, got %d", report.RiskScore)
	}

	if len(report.Violations) == 0 {
		t.Errorf("Expected violations, got none")
	}

	if len(report.Remediations) == 0 {
		t.Errorf("Expected remediations, got none")
	}
}
