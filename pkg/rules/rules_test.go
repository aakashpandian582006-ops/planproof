package rules

import (
	"testing"
)

func TestStatefulDestructionRule(t *testing.T) {
	engine := NewRuleEngine()

	// 1. Destructive stateful resource
	destructiveDB := []ResourceChange{
		{
			Address: "aws_db_instance.main",
			Type:    "aws_db_instance",
			Name:    "main",
			Change: struct {
				Actions []string               `json:"actions"`
				Before  map[string]interface{} `json:"before"`
				After   map[string]interface{} `json:"after"`
			}{
				Actions: []string{"destroy"},
			},
		},
	}

	violations := engine.Evaluate(destructiveDB)
	if len(violations) != 1 {
		t.Fatalf("Expected 1 violation, got %d", len(violations))
	}
	if violations[0].Severity != SeverityCritical {
		t.Errorf("Expected CRITICAL severity, got %s", violations[0].Severity)
	}
	if violations[0].RuleID != "STATE-001" {
		t.Errorf("Expected STATE-001, got %s", violations[0].RuleID)
	}

	// 2. Safe create action
	createDB := []ResourceChange{
		{
			Address: "aws_db_instance.main",
			Type:    "aws_db_instance",
			Name:    "main",
			Change: struct {
				Actions []string               `json:"actions"`
				Before  map[string]interface{} `json:"before"`
				After   map[string]interface{} `json:"after"`
			}{
				Actions: []string{"create"},
			},
		},
	}
	if v := engine.Evaluate(createDB); len(v) != 0 {
		t.Errorf("Expected 0 violations for create, got %d", len(v))
	}
}

func TestS3EncryptionRule(t *testing.T) {
	engine := NewRuleEngine()

	// 1. Unencrypted S3 bucket
	unencryptedBucket := []ResourceChange{
		{
			Address: "aws_s3_bucket.logs",
			Type:    "aws_s3_bucket",
			Name:    "logs",
			Change: struct {
				Actions []string               `json:"actions"`
				Before  map[string]interface{} `json:"before"`
				After   map[string]interface{} `json:"after"`
			}{
				Actions: []string{"create"},
				After: map[string]interface{}{
					"bucket": "my-unencrypted-logs",
				},
			},
		},
	}

	violations := engine.Evaluate(unencryptedBucket)
	if len(violations) != 1 {
		t.Fatalf("Expected 1 violation, got %d", len(violations))
	}
	if violations[0].RuleID != "AWS-S3-001" {
		t.Errorf("Expected AWS-S3-001, got %s", violations[0].RuleID)
	}
	if violations[0].Severity != SeverityHigh {
		t.Errorf("Expected HIGH severity, got %s", violations[0].Severity)
	}

	// 2. Encrypted S3 bucket (inline)
	encryptedBucket := []ResourceChange{
		{
			Address: "aws_s3_bucket.logs",
			Type:    "aws_s3_bucket",
			Name:    "logs",
			Change: struct {
				Actions []string               `json:"actions"`
				Before  map[string]interface{} `json:"before"`
				After   map[string]interface{} `json:"after"`
			}{
				Actions: []string{"create"},
				After: map[string]interface{}{
					"bucket": "my-encrypted-logs",
					"server_side_encryption_configuration": []interface{}{
						map[string]interface{}{
							"rule": map[string]interface{}{
								"apply_server_side_encryption_by_default": map[string]interface{}{
									"sse_algorithm": "AES256",
								},
							},
						},
					},
				},
			},
		},
	}
	if v := engine.Evaluate(encryptedBucket); len(v) != 0 {
		t.Errorf("Expected 0 violations for encrypted bucket, got %d", len(v))
	}
}

func TestOpenSSHRule(t *testing.T) {
	engine := NewRuleEngine()

	// 1. Open SSH in security group ingress
	openSG := []ResourceChange{
		{
			Address: "aws_security_group.allow_all",
			Type:    "aws_security_group",
			Name:    "allow_all",
			Change: struct {
				Actions []string               `json:"actions"`
				Before  map[string]interface{} `json:"before"`
				After   map[string]interface{} `json:"after"`
			}{
				Actions: []string{"create"},
				After: map[string]interface{}{
					"ingress": []interface{}{
						map[string]interface{}{
							"cidr_blocks": []interface{}{"0.0.0.0/0"},
							"from_port":   float64(22),
							"to_port":     float64(22),
							"protocol":    "tcp",
						},
					},
				},
			},
		},
	}

	violations := engine.Evaluate(openSG)
	if len(violations) != 1 {
		t.Fatalf("Expected 1 violation for open SSH, got %d", len(violations))
	}
	if violations[0].RuleID != "AWS-SG-001" {
		t.Errorf("Expected AWS-SG-001, got %s", violations[0].RuleID)
	}
	if violations[0].Severity != SeverityCritical {
		t.Errorf("Expected CRITICAL severity, got %s", violations[0].Severity)
	}

	// 2. Restricted SSH (private CIDR)
	restrictedSG := []ResourceChange{
		{
			Address: "aws_security_group.private_ssh",
			Type:    "aws_security_group",
			Name:    "private_ssh",
			Change: struct {
				Actions []string               `json:"actions"`
				Before  map[string]interface{} `json:"before"`
				After   map[string]interface{} `json:"after"`
			}{
				Actions: []string{"create"},
				After: map[string]interface{}{
					"ingress": []interface{}{
						map[string]interface{}{
							"cidr_blocks": []interface{}{"10.0.0.0/16"},
							"from_port":   float64(22),
							"to_port":     float64(22),
							"protocol":    "tcp",
						},
					},
				},
			},
		},
	}
	if v := engine.Evaluate(restrictedSG); len(v) != 0 {
		t.Errorf("Expected 0 violations for restricted SSH, got %d", len(v))
	}
}

func TestIAMWildcardRule(t *testing.T) {
	engine := NewRuleEngine()

	// 1. Full admin wildcard (Action: *, Resource: *) -> CRITICAL
	adminPolicy := []ResourceChange{
		{
			Address: "aws_iam_policy.admin",
			Type:    "aws_iam_policy",
			Name:    "admin",
			Change: struct {
				Actions []string               `json:"actions"`
				Before  map[string]interface{} `json:"before"`
				After   map[string]interface{} `json:"after"`
			}{
				Actions: []string{"create"},
				After: map[string]interface{}{
					"policy": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
				},
			},
		},
	}

	violations := engine.Evaluate(adminPolicy)
	if len(violations) != 1 {
		t.Fatalf("Expected 1 violation for admin policy, got %d", len(violations))
	}
	if violations[0].RuleID != "AWS-IAM-001" {
		t.Errorf("Expected AWS-IAM-001, got %s", violations[0].RuleID)
	}
	if violations[0].Severity != SeverityCritical {
		t.Errorf("Expected CRITICAL severity, got %s", violations[0].Severity)
	}

	// 2. Service wildcard on all resources -> HIGH
	s3WildcardPolicy := []ResourceChange{
		{
			Address: "aws_iam_policy.s3_wildcard",
			Type:    "aws_iam_policy",
			Name:    "s3_wildcard",
			Change: struct {
				Actions []string               `json:"actions"`
				Before  map[string]interface{} `json:"before"`
				After   map[string]interface{} `json:"after"`
			}{
				Actions: []string{"create"},
				After: map[string]interface{}{
					"policy": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":"*"}]}`,
				},
			},
		},
	}

	violations = engine.Evaluate(s3WildcardPolicy)
	if len(violations) != 1 {
		t.Fatalf("Expected 1 violation for s3 wildcard, got %d", len(violations))
	}
	if violations[0].Severity != SeverityHigh {
		t.Errorf("Expected HIGH severity, got %s", violations[0].Severity)
	}

	// 3. Least privilege policy -> No violation
	safePolicy := []ResourceChange{
		{
			Address: "aws_iam_policy.read_bucket",
			Type:    "aws_iam_policy",
			Name:    "read_bucket",
			Change: struct {
				Actions []string               `json:"actions"`
				Before  map[string]interface{} `json:"before"`
				After   map[string]interface{} `json:"after"`
			}{
				Actions: []string{"create"},
				After: map[string]interface{}{
					"policy": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::my-bucket/*"}]}`,
				},
			},
		},
	}
	if v := engine.Evaluate(safePolicy); len(v) != 0 {
		t.Errorf("Expected 0 violations for safe policy, got %d", len(v))
	}
}
