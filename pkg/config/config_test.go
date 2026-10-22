package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Gate.Threshold != 50 {
		t.Errorf("Expected default threshold 50, got %d", cfg.Gate.Threshold)
	}
	if !cfg.Gate.FailOnCritical {
		t.Errorf("Expected default FailOnCritical to be true")
	}
	if cfg.Gate.FailOnHigh {
		t.Errorf("Expected default FailOnHigh to be false")
	}
	if !cfg.IsRuleEnabled("STATE-001") {
		t.Errorf("Expected STATE-001 to be enabled by default")
	}
	if cfg.GetRuleRiskScore("AWS-S3-001", "HIGH", 20) != 25 {
		t.Errorf("Expected AWS-S3-001 score to be 25, got %d", cfg.GetRuleRiskScore("AWS-S3-001", "HIGH", 20))
	}
}

func TestLoadConfig(t *testing.T) {
	yamlContent := `
version: "1.1"
name: "Custom Security Gate"
gate:
  threshold: 30
  fail_on_critical: true
  fail_on_high: true
severity_weights:
  critical: 60
  high: 30
  medium: 10
  low: 2
rules:
  STATE-001:
    enabled: false
  AWS-S3-001:
    enabled: true
    risk_score: 40
    severity: "CRITICAL"
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test_policy.yaml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write temporary test config: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.Name != "Custom Security Gate" {
		t.Errorf("Expected name 'Custom Security Gate', got '%s'", cfg.Name)
	}
	if cfg.Gate.Threshold != 30 {
		t.Errorf("Expected threshold 30, got %d", cfg.Gate.Threshold)
	}
	if !cfg.Gate.FailOnHigh {
		t.Errorf("Expected FailOnHigh to be true")
	}
	if cfg.IsRuleEnabled("STATE-001") {
		t.Errorf("Expected STATE-001 to be disabled")
	}
	if !cfg.IsRuleEnabled("AWS-S3-001") {
		t.Errorf("Expected AWS-S3-001 to be enabled")
	}
	if cfg.GetRuleSeverity("AWS-S3-001", "HIGH") != "CRITICAL" {
		t.Errorf("Expected AWS-S3-001 severity override to CRITICAL")
	}
	if cfg.GetRuleRiskScore("AWS-S3-001", "CRITICAL", 25) != 40 {
		t.Errorf("Expected risk score 40, got %d", cfg.GetRuleRiskScore("AWS-S3-001", "CRITICAL", 25))
	}
}
