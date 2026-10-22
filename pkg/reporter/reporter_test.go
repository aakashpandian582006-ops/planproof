package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"planproof/pkg/analyzer"
	"planproof/pkg/rules"
)

func TestExportJSON_And_HTML(t *testing.T) {
	riskReport := &analyzer.RiskReport{
		IsUnsafe:     true,
		GateStatus:   "FAILED",
		RiskScore:    50,
		Threshold:    50,
		TotalChanges: 2,
		Summary: analyzer.SeveritySummary{
			Critical: 1,
			High:     0,
			Medium:   0,
			Low:      0,
		},
		RuleViolations: []rules.Violation{
			{
				RuleID:          "STATE-001",
				RuleName:        "Stateful Resource Destruction Guard",
				Severity:        rules.SeverityCritical,
				ResourceAddress: "aws_db_instance.prod",
				ResourceType:    "aws_db_instance",
				Description:     "Scheduled for destruction",
				Remediation:     "Add prevent_destroy",
				RiskScore:       50,
			},
		},
	}

	data := BuildReportData("testdata/plan.json", riskReport)

	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "report.json")
	htmlPath := filepath.Join(tmpDir, "report.html")

	// 1. Test JSON Export
	if err := ExportJSON(data, jsonPath); err != nil {
		t.Fatalf("ExportJSON failed: %v", err)
	}

	jsonBytes, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("Failed to read exported JSON: %v", err)
	}

	var parsed ReportData
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal exported JSON: %v", err)
	}

	if parsed.GateStatus != "FAILED" {
		t.Errorf("Expected GateStatus FAILED, got %s", parsed.GateStatus)
	}
	if parsed.RiskScore != 50 {
		t.Errorf("Expected RiskScore 50, got %d", parsed.RiskScore)
	}
	if len(parsed.RuleViolations) != 1 {
		t.Errorf("Expected 1 rule violation, got %d", len(parsed.RuleViolations))
	}

	// 2. Test HTML Export
	if err := ExportHTML(data, htmlPath); err != nil {
		t.Fatalf("ExportHTML failed: %v", err)
	}

	htmlBytes, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("Failed to read exported HTML: %v", err)
	}
	htmlStr := string(htmlBytes)

	if !strings.Contains(htmlStr, "GATE STATUS: [FAILED]") {
		t.Errorf("Expected HTML to contain GATE STATUS: [FAILED]")
	}
	if !strings.Contains(htmlStr, "STATE-001") {
		t.Errorf("Expected HTML to contain STATE-001")
	}
	if !strings.Contains(htmlStr, "aws_db_instance.prod") {
		t.Errorf("Expected HTML to contain aws_db_instance.prod")
	}
	if !strings.Contains(htmlStr, "Add prevent_destroy") {
		t.Errorf("Expected HTML to contain remediation text")
	}
}

func TestExportHTML_SafePlan(t *testing.T) {
	riskReport := &analyzer.RiskReport{
		IsUnsafe:       false,
		GateStatus:     "PASSED",
		RiskScore:      0,
		Threshold:      50,
		TotalChanges:   1,
		Summary:        analyzer.SeveritySummary{},
		RuleViolations: []rules.Violation{},
	}

	data := BuildReportData("testdata/safe_plan.json", riskReport)

	tmpDir := t.TempDir()
	htmlPath := filepath.Join(tmpDir, "report_safe.html")

	if err := ExportHTML(data, htmlPath); err != nil {
		t.Fatalf("ExportHTML failed for safe plan: %v", err)
	}

	htmlBytes, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("Failed to read exported HTML: %v", err)
	}
	htmlStr := string(htmlBytes)

	if !strings.Contains(htmlStr, "GATE STATUS: [PASSED]") {
		t.Errorf("Expected HTML to contain GATE STATUS: [PASSED]")
	}
	if !strings.Contains(htmlStr, "Zero Violations Detected") {
		t.Errorf("Expected HTML to contain 'Zero Violations Detected'")
	}
}
