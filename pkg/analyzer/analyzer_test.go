package analyzer

import (
	"testing"

	"planproof/pkg/config"
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

func TestAnalyzePlan_SecurityRulesIntegration(t *testing.T) {
	planJSON := []byte(`{
		"format_version": "1.2",
		"terraform_version": "1.5.0",
		"resource_changes": [
			{
				"address": "aws_s3_bucket.data_bucket",
				"type": "aws_s3_bucket",
				"name": "data_bucket",
				"change": {
					"actions": ["create"],
					"after": {
						"bucket": "customer-data"
					}
				}
			},
			{
				"address": "aws_security_group.ingress_sg",
				"type": "aws_security_group",
				"name": "ingress_sg",
				"change": {
					"actions": ["create"],
					"after": {
						"ingress": [
							{
								"cidr_blocks": ["0.0.0.0/0"],
								"from_port": 22,
								"to_port": 22,
								"protocol": "tcp"
							}
						]
					}
				}
			},
			{
				"address": "aws_iam_policy.wildcard_policy",
				"type": "aws_iam_policy",
				"name": "wildcard_policy",
				"change": {
					"actions": ["create"],
					"after": {
						"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
					}
				}
			}
		]
	}`)

	report, err := AnalyzePlan(planJSON)
	if err != nil {
		t.Fatalf("AnalyzePlan failed: %v", err)
	}

	if !report.IsUnsafe {
		t.Errorf("Expected plan to be unsafe, got safe")
	}

	if report.Summary.Critical < 2 {
		t.Errorf("Expected at least 2 CRITICAL violations (SSH + IAM Admin), got %d", report.Summary.Critical)
	}

	if report.Summary.High < 1 {
		t.Errorf("Expected at least 1 HIGH violation (S3 Unencrypted), got %d", report.Summary.High)
	}

	if report.RiskScore < 100 {
		t.Errorf("Expected risk score >= 100, got %d", report.RiskScore)
	}

	if len(report.RuleViolations) != 3 {
		t.Errorf("Expected exactly 3 rule violations, got %d", len(report.RuleViolations))
	}
}

func TestAnalyzePlanWithThreshold(t *testing.T) {
	// A plan with only HIGH severity (25 risk points)
	s3PlanJSON := []byte(`{
		"format_version": "1.2",
		"terraform_version": "1.5.0",
		"resource_changes": [
			{
				"address": "aws_s3_bucket.logs",
				"type": "aws_s3_bucket",
				"name": "logs",
				"change": {
					"actions": ["create"],
					"after": {
						"bucket": "app-logs"
					}
				}
			}
		]
	}`)

	// If threshold is 10, a 25-point violation fails
	reportLowThreshold, err := AnalyzePlanWithThreshold(s3PlanJSON, 10)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !reportLowThreshold.IsUnsafe {
		t.Errorf("Expected IsUnsafe true with threshold 10, got false")
	}

	// If threshold is 50, a 25-point non-critical violation passes
	reportHighThreshold, err := AnalyzePlanWithThreshold(s3PlanJSON, 50)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if reportHighThreshold.IsUnsafe {
		t.Errorf("Expected IsUnsafe false with threshold 50, got true")
	}
}

func TestAnalyzePlanWithPolicy(t *testing.T) {
	s3PlanJSON := []byte(`{
		"format_version": "1.2",
		"terraform_version": "1.5.0",
		"resource_changes": [
			{
				"address": "aws_s3_bucket.logs",
				"type": "aws_s3_bucket",
				"name": "logs",
				"change": {
					"actions": ["create"],
					"after": {
						"bucket": "app-logs"
					}
				}
			}
		]
	}`)

	// Test 1: Rule disabled via policy
	cfgDisabled := config.DefaultConfig()
	disabled := false
	cfgDisabled.Rules["AWS-S3-001"] = config.RuleConfig{
		Enabled: &disabled,
	}

	reportDisabled, err := AnalyzePlanWithPolicy(s3PlanJSON, cfgDisabled)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(reportDisabled.RuleViolations) != 0 {
		t.Errorf("Expected 0 violations when rule is disabled, got %d", len(reportDisabled.RuleViolations))
	}
	if reportDisabled.IsUnsafe {
		t.Errorf("Expected plan to pass when rule is disabled")
	}

	// Test 2: Custom risk score override via policy
	cfgScore := config.DefaultConfig()
	customScore := 60
	cfgScore.Rules["AWS-S3-001"] = config.RuleConfig{
		RiskScore: &customScore,
	}
	reportScore, err := AnalyzePlanWithPolicy(s3PlanJSON, cfgScore)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if reportScore.RiskScore != 60 {
		t.Errorf("Expected risk score 60, got %d", reportScore.RiskScore)
	}
	if !reportScore.IsUnsafe {
		t.Errorf("Expected plan to fail when risk score 60 >= threshold 50")
	}
}

