package analyzer

import (
	"os"
	"testing"
)

func TestAnalyzePlan_Safe(t *testing.T) {
	data, err := os.ReadFile("../../testdata/safe_plan.json")
	if err != nil {
		t.Fatalf("Failed to read safe_plan.json: %v", err)
	}

	report, err := AnalyzePlan(data)
	if err != nil {
		t.Fatalf("AnalyzePlan failed: %v", err)
	}

	if report.IsUnsafe {
		t.Errorf("Expected plan to be safe, but got unsafe with %d violations", len(report.Violations))
	}
}

func TestAnalyzePlan_Unsafe(t *testing.T) {
	data, err := os.ReadFile("../../testdata/unsafe_plan.json")
	if err != nil {
		t.Fatalf("Failed to read unsafe_plan.json: %v", err)
	}

	report, err := AnalyzePlan(data)
	if err != nil {
		t.Fatalf("AnalyzePlan failed: %v", err)
	}

	if !report.IsUnsafe {
		t.Errorf("Expected plan to be flagged as unsafe due to stateful destruction, but passed")
	}

	if len(report.Violations) == 0 {
		t.Errorf("Expected violations in report, got none")
	}
}
