package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"planproof/pkg/analyzer"
	"planproof/pkg/rules"
)

func TestSendAlert_Success(t *testing.T) {
	var receivedPayload WebhookPayload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected application/json header, got %s", r.Header.Get("Content-Type"))
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Failed to read request body: %v", err)
		}
		if err := json.Unmarshal(body, &receivedPayload); err != nil {
			t.Fatalf("Failed to unmarshal request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	report := &analyzer.RiskReport{
		IsUnsafe:   true,
		GateStatus: "FAILED",
		RiskScore:  60,
		Threshold:  50,
		Summary: analyzer.SeveritySummary{
			Critical: 1,
		},
		RuleViolations: []rules.Violation{
			{
				RuleID:          "STATE-001",
				Severity:        rules.SeverityCritical,
				ResourceAddress: "aws_db_instance.primary",
				RiskScore:       50,
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := SendAlert(ctx, ts.URL, "test_plan.json", report)
	if err != nil {
		t.Fatalf("SendAlert failed: %v", err)
	}

	if receivedPayload.Metadata.RiskScore != 60 {
		t.Errorf("Expected metadata risk score 60, got %d", receivedPayload.Metadata.RiskScore)
	}
	if len(receivedPayload.Attachments) == 0 {
		t.Errorf("Expected attachments in webhook payload")
	}
}

func TestSendAlert_EmptyURL(t *testing.T) {
	err := SendAlert(context.Background(), "", "plan.json", &analyzer.RiskReport{})
	if err != nil {
		t.Errorf("Expected no error when webhook URL is empty, got %v", err)
	}
}

func TestSendAlert_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	report := &analyzer.RiskReport{IsUnsafe: true}
	err := SendAlert(context.Background(), ts.URL, "plan.json", report)
	if err == nil {
		t.Errorf("Expected error when server returns 500, got nil")
	}
}
