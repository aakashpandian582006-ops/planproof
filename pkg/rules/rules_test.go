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

func TestRDSPublicAccessRule(t *testing.T) {
	engine := NewRuleEngine()

	// 1. Unsafe publicly accessible RDS
	publicRDS := []ResourceChange{
		{
			Address: "aws_db_instance.analytics",
			Type:    "aws_db_instance",
			Name:    "analytics",
			Change: struct {
				Actions []string               `json:"actions"`
				Before  map[string]interface{} `json:"before"`
				After   map[string]interface{} `json:"after"`
			}{
				Actions: []string{"create"},
				After: map[string]interface{}{
					"publicly_accessible": true,
				},
			},
		},
	}

	violations := engine.Evaluate(publicRDS)
	if len(violations) != 1 {
		t.Fatalf("Expected 1 violation for public RDS, got %d", len(violations))
	}
	if violations[0].RuleID != "AWS-RDS-001" {
		t.Errorf("Expected AWS-RDS-001, got %s", violations[0].RuleID)
	}
	if violations[0].Severity != SeverityCritical {
		t.Errorf("Expected CRITICAL, got %s", violations[0].Severity)
	}

	// 2. Safe private RDS
	privateRDS := []ResourceChange{
		{
			Address: "aws_db_instance.analytics",
			Type:    "aws_db_instance",
			Name:    "analytics",
			Change: struct {
				Actions []string               `json:"actions"`
				Before  map[string]interface{} `json:"before"`
				After   map[string]interface{} `json:"after"`
			}{
				Actions: []string{"create"},
				After: map[string]interface{}{
					"publicly_accessible": false,
				},
			},
		},
	}
	if v := engine.Evaluate(privateRDS); len(v) != 0 {
		t.Errorf("Expected 0 violations for private RDS, got %d", len(v))
	}
}

func TestAzureRules(t *testing.T) {
	engine := NewRuleEngine()

	// 1. Azure Storage public access
	storagePublic := []ResourceChange{
		{
			Address: "azurerm_storage_account.data",
			Type:    "azurerm_storage_account",
			Name:    "data",
			Change: struct {
				Actions []string               `json:"actions"`
				Before  map[string]interface{} `json:"before"`
				After   map[string]interface{} `json:"after"`
			}{
				Actions: []string{"create"},
				After: map[string]interface{}{
					"allow_nested_items_to_be_public": true,
				},
			},
		},
	}
	v := engine.Evaluate(storagePublic)
	if len(v) != 1 || v[0].RuleID != "AZURE-BLOB-001" {
		t.Errorf("Expected AZURE-BLOB-001 violation, got %v", v)
	}

	// 2. Azure PostgreSQL 0.0.0.0 firewall
	fwRule := []ResourceChange{
		{
			Address: "azurerm_postgresql_firewall_rule.allow_all",
			Type:    "azurerm_postgresql_firewall_rule",
			Name:    "allow_all",
			Change: struct {
				Actions []string               `json:"actions"`
				Before  map[string]interface{} `json:"before"`
				After   map[string]interface{} `json:"after"`
			}{
				Actions: []string{"create"},
				After: map[string]interface{}{
					"start_ip_address": "0.0.0.0",
					"end_ip_address":   "255.255.255.255",
				},
			},
		},
	}
	v2 := engine.Evaluate(fwRule)
	if len(v2) != 1 || v2[0].RuleID != "AZURE-SQL-001" {
		t.Errorf("Expected AZURE-SQL-001 violation, got %v", v2)
	}
}

func TestGCPRules(t *testing.T) {
	engine := NewRuleEngine()

	// 1. GCP Storage Bucket missing UBLA
	gcsBucket := []ResourceChange{
		{
			Address: "google_storage_bucket.reports",
			Type:    "google_storage_bucket",
			Name:    "reports",
			Change: struct {
				Actions []string               `json:"actions"`
				Before  map[string]interface{} `json:"before"`
				After   map[string]interface{} `json:"after"`
			}{
				Actions: []string{"create"},
				After: map[string]interface{}{
					"uniform_bucket_level_access": false,
				},
			},
		},
	}
	v := engine.Evaluate(gcsBucket)
	if len(v) != 1 || v[0].RuleID != "GCP-GCS-001" {
		t.Errorf("Expected GCP-GCS-001 violation, got %v", v)
	}

	// 2. GCP SQL 0.0.0.0/0 Authorized Network
	gcpSQL := []ResourceChange{
		{
			Address: "google_sql_database_instance.postgres",
			Type:    "google_sql_database_instance",
			Name:    "postgres",
			Change: struct {
				Actions []string               `json:"actions"`
				Before  map[string]interface{} `json:"before"`
				After   map[string]interface{} `json:"after"`
			}{
				Actions: []string{"create"},
				After: map[string]interface{}{
					"settings": map[string]interface{}{
						"ip_configuration": map[string]interface{}{
							"authorized_networks": []interface{}{
								map[string]interface{}{
									"name":  "internet",
									"value": "0.0.0.0/0",
								},
							},
						},
					},
				},
			},
		},
	}
	v2 := engine.Evaluate(gcpSQL)
	if len(v2) != 1 || v2[0].RuleID != "GCP-SQL-001" {
		t.Errorf("Expected GCP-SQL-001 violation, got %v", v2)
	}
}

