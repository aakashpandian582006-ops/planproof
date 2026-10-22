package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"planproof/pkg/analyzer"
)

// WebhookPayload represents the standard JSON payload dispatched to Slack, Teams, or generic webhook receivers.
type WebhookPayload struct {
	Text        string        `json:"text"`
	Username    string        `json:"username,omitempty"`
	IconEmoji   string        `json:"icon_emoji,omitempty"`
	Attachments []Attachment  `json:"attachments,omitempty"`
	Metadata    AlertMetadata `json:"metadata"`
}

// Attachment formats Slack/Teams compatible colored cards.
type Attachment struct {
	Color     string  `json:"color"`
	Title     string  `json:"title"`
	TitleLink string  `json:"title_link,omitempty"`
	Text      string  `json:"text"`
	Fields    []Field `json:"fields,omitempty"`
	Footer    string  `json:"footer"`
	Timestamp int64   `json:"ts"`
}

// Field represents an individual key-value data point in an alert attachment.
type Field struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// AlertMetadata carries machine-readable gate analysis findings for SIEM ingestion.
type AlertMetadata struct {
	Tool            string                   `json:"tool"`
	Version         string                   `json:"version"`
	PlanFile        string                   `json:"plan_file"`
	GateStatus      string                   `json:"gate_status"`
	IsUnsafe        bool                     `json:"is_unsafe"`
	RiskScore       int                      `json:"risk_score"`
	Threshold       int                      `json:"threshold"`
	SeveritySummary analyzer.SeveritySummary `json:"severity_summary"`
	TotalViolations int                      `json:"total_violations"`
}

// SendAlert dispatches an alert payload to the specified webhook URL.
func SendAlert(ctx context.Context, webhookURL string, planFile string, report *analyzer.RiskReport) error {
	if webhookURL == "" {
		return nil
	}

	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
	}

	payload := BuildWebhookPayload(planFile, report)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to encode webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to construct webhook HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "PlanProof-RiskGate/1.2.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook endpoint returned non-2xx status code: %d", resp.StatusCode)
	}

	return nil
}

// BuildWebhookPayload crafts a rich alert payload for chat platforms and SIEM webhooks.
func BuildWebhookPayload(planFile string, report *analyzer.RiskReport) *WebhookPayload {
	statusEmoji := "🚨"
	cardColor := "#EF4444" // Crimson red
	statusTitle := "[FAILED] UNACCEPTABLE RISK DETECTED"
	summaryText := fmt.Sprintf("PlanProof halted deployment pipeline for '%s'. Risk score %d (threshold: %d).", planFile, report.RiskScore, report.Threshold)

	if !report.IsUnsafe {
		statusEmoji = "✅"
		cardColor = "#10B981" // Emerald green
		statusTitle = "[PASSED] SAFE TO APPLY"
		summaryText = fmt.Sprintf("PlanProof verified '%s'. All architectural and security gates satisfied.", planFile)
	}

	var fields []Field
	fields = append(fields, Field{
		Title: "Target Plan",
		Value: planFile,
		Short: true,
	})
	fields = append(fields, Field{
		Title: "Risk Score / Threshold",
		Value: fmt.Sprintf("%d / %d", report.RiskScore, report.Threshold),
		Short: true,
	})
	fields = append(fields, Field{
		Title: "Severity Breakdown",
		Value: fmt.Sprintf("CRITICAL: %d | HIGH: %d | MEDIUM: %d | LOW: %d",
			report.Summary.Critical, report.Summary.High, report.Summary.Medium, report.Summary.Low),
		Short: false,
	})

	if len(report.RuleViolations) > 0 {
		var violationSummaries string
		limit := 4
		for i, v := range report.RuleViolations {
			if i >= limit {
				violationSummaries += fmt.Sprintf("• ... and %d more violations\n", len(report.RuleViolations)-limit)
				break
			}
			violationSummaries += fmt.Sprintf("• [%s] %s: %s (+%d pts)\n", v.Severity, v.RuleID, v.ResourceAddress, v.RiskScore)
		}
		fields = append(fields, Field{
			Title: "Detected Violations",
			Value: violationSummaries,
			Short: false,
		})
	}

	attachment := Attachment{
		Color:     cardColor,
		Title:     fmt.Sprintf("%s PlanProof Risk Gate: %s", statusEmoji, statusTitle),
		Text:      summaryText,
		Fields:    fields,
		Footer:    "PlanProof IaC Security Engine",
		Timestamp: time.Now().Unix(),
	}

	return &WebhookPayload{
		Text:      fmt.Sprintf("%s *PlanProof Alert*: %s", statusEmoji, summaryText),
		Username:  "PlanProof Sentinel",
		IconEmoji: ":shield:",
		Attachments: []Attachment{
			attachment,
		},
		Metadata: AlertMetadata{
			Tool:            "PlanProof",
			Version:         "1.2.0",
			PlanFile:        planFile,
			GateStatus:      report.GateStatus,
			IsUnsafe:        report.IsUnsafe,
			RiskScore:       report.RiskScore,
			Threshold:       report.Threshold,
			SeveritySummary: report.Summary,
			TotalViolations: len(report.RuleViolations),
		},
	}
}
