package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// GateConfig defines deployment gate thresholds and failure triggers.
type GateConfig struct {
	Threshold      int  `yaml:"threshold" json:"threshold"`
	FailOnCritical bool `yaml:"fail_on_critical" json:"fail_on_critical"`
	FailOnHigh     bool `yaml:"fail_on_high" json:"fail_on_high"`
}

// RuleConfig defines per-rule configuration overrides.
type RuleConfig struct {
	Name      string `yaml:"name" json:"name"`
	Enabled   *bool  `yaml:"enabled" json:"enabled"`
	Severity  string `yaml:"severity" json:"severity"`
	RiskScore *int   `yaml:"risk_score" json:"risk_score"`
}

// SeverityWeights defines default risk points per severity level.
type SeverityWeights struct {
	Critical int `yaml:"critical" json:"critical"`
	High     int `yaml:"high" json:"high"`
	Medium   int `yaml:"medium" json:"medium"`
	Low      int `yaml:"low" json:"low"`
}

// PolicyConfig captures the complete security and risk gate policy.
type PolicyConfig struct {
	Version         string                `yaml:"version" json:"version"`
	Name            string                `yaml:"name" json:"name"`
	Gate            GateConfig            `yaml:"gate" json:"gate"`
	SeverityWeights SeverityWeights       `yaml:"severity_weights" json:"severity_weights"`
	Rules           map[string]RuleConfig `yaml:"rules" json:"rules"`
}

// DefaultConfig returns an enterprise baseline configuration.
func DefaultConfig() *PolicyConfig {
	enabled := true
	return &PolicyConfig{
		Version: "1.0",
		Name:    "Enterprise Baseline Security Policy",
		Gate: GateConfig{
			Threshold:      50,
			FailOnCritical: true,
			FailOnHigh:     false,
		},
		SeverityWeights: SeverityWeights{
			Critical: 50,
			High:     25,
			Medium:   15,
			Low:      5,
		},
		Rules: map[string]RuleConfig{
			"STATE-001": {
				Name:      "Stateful Resource Destruction Guard",
				Enabled:   &enabled,
				Severity:  "CRITICAL",
				RiskScore: intPtr(50),
			},
			"AWS-S3-001": {
				Name:      "S3 Bucket Missing Server-Side Encryption",
				Enabled:   &enabled,
				Severity:  "HIGH",
				RiskScore: intPtr(25),
			},
			"AWS-S3-002": {
				Name:      "S3 Bucket Public ACL Allowed",
				Enabled:   &enabled,
				Severity:  "CRITICAL",
				RiskScore: intPtr(50),
			},
			"AWS-SG-001": {
				Name:      "Security Group Ingress Allows Open SSH Access (0.0.0.0/0)",
				Enabled:   &enabled,
				Severity:  "CRITICAL",
				RiskScore: intPtr(50),
			},
			"AWS-SG-002": {
				Name:      "Security Group Ingress Allows Open RDP Access (0.0.0.0/0)",
				Enabled:   &enabled,
				Severity:  "HIGH",
				RiskScore: intPtr(35),
			},
			"AWS-IAM-001": {
				Name:      "IAM Policy Grants Wildcard Admin Privileges (*:*)",
				Enabled:   &enabled,
				Severity:  "CRITICAL",
				RiskScore: intPtr(50),
			},
			"AWS-RDS-001": {
				Name:      "RDS Instance Publicly Accessible",
				Enabled:   &enabled,
				Severity:  "CRITICAL",
				RiskScore: intPtr(50),
			},
			"AZURE-BLOB-001": {
				Name:      "Azure Storage Account Allows Public Blob Access",
				Enabled:   &enabled,
				Severity:  "CRITICAL",
				RiskScore: intPtr(50),
			},
			"AZURE-SQL-001": {
				Name:      "Azure Database Firewall Allows 0.0.0.0 Open Ingress",
				Enabled:   &enabled,
				Severity:  "CRITICAL",
				RiskScore: intPtr(50),
			},
			"GCP-GCS-001": {
				Name:      "GCP Storage Bucket Missing Uniform Bucket-Level Access",
				Enabled:   &enabled,
				Severity:  "HIGH",
				RiskScore: intPtr(25),
			},
			"GCP-SQL-001": {
				Name:      "GCP Cloud SQL Allows Unrestricted Ingress (0.0.0.0/0)",
				Enabled:   &enabled,
				Severity:  "CRITICAL",
				RiskScore: intPtr(50),
			},
		},
	}
}

// LoadConfig parses a YAML policy configuration file with defaults.
func LoadConfig(path string) (*PolicyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy config file '%s': %w", path, err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse YAML policy config: %w", err)
	}

	if cfg.Gate.Threshold <= 0 {
		cfg.Gate.Threshold = 50
	}

	return cfg, nil
}

// IsRuleEnabled checks if a specific rule is active in the policy.
func (c *PolicyConfig) IsRuleEnabled(ruleID string) bool {
	if c == nil || c.Rules == nil {
		return true
	}
	if r, ok := c.Rules[ruleID]; ok {
		if r.Enabled != nil {
			return *r.Enabled
		}
	}
	return true
}

// GetRuleSeverity returns the configured severity or default.
func (c *PolicyConfig) GetRuleSeverity(ruleID string, defaultSeverity string) string {
	if c == nil || c.Rules == nil {
		return defaultSeverity
	}
	if r, ok := c.Rules[ruleID]; ok && r.Severity != "" {
		return strings.ToUpper(r.Severity)
	}
	return defaultSeverity
}

// GetRuleRiskScore calculates the risk score applying overrides or severity weights.
func (c *PolicyConfig) GetRuleRiskScore(ruleID string, severity string, defaultScore int) int {
	if c == nil {
		return defaultScore
	}
	// Direct rule risk score override
	if r, ok := c.Rules[ruleID]; ok && r.RiskScore != nil {
		return *r.RiskScore
	}
	// Fallback to configured severity weights if rule score wasn't explicitly set
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		if c.SeverityWeights.Critical > 0 {
			return c.SeverityWeights.Critical
		}
	case "HIGH":
		if c.SeverityWeights.High > 0 {
			return c.SeverityWeights.High
		}
	case "MEDIUM":
		if c.SeverityWeights.Medium > 0 {
			return c.SeverityWeights.Medium
		}
	case "LOW":
		if c.SeverityWeights.Low > 0 {
			return c.SeverityWeights.Low
		}
	}
	return defaultScore
}

func intPtr(i int) *int {
	return &i
}
