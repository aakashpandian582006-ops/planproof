package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"

	"planproof/pkg/analyzer"
	"planproof/pkg/rules"
)

// ReportData consolidates all metrics, findings, and metadata for report export.
type ReportData struct {
	Timestamp             time.Time                `json:"timestamp"`
	Tool                  string                   `json:"tool"`
	Version               string                   `json:"version"`
	TargetPlan            string                   `json:"target_plan"`
	PolicyName            string                   `json:"policy_name"`
	PolicyVersion         string                   `json:"policy_version"`
	GateStatus            string                   `json:"gate_status"`
	IsUnsafe              bool                     `json:"is_unsafe"`
	GateAction            string                   `json:"gate_action"`
	RiskScore             int                      `json:"risk_score"`
	Threshold             int                      `json:"threshold"`
	TotalChangesEvaluated int                      `json:"total_changes_evaluated"`
	TotalViolations       int                      `json:"total_violations"`
	SeveritySummary       analyzer.SeveritySummary `json:"severity_summary"`
	RuleViolations        []rules.Violation        `json:"rule_violations"`
}

// BuildReportData creates a ReportData instance from an analysis result.
func BuildReportData(targetPlan string, report *analyzer.RiskReport) *ReportData {
	gateStatus := "PASSED"
	gateAction := "Deployment approved. All security and state-safety gates satisfied."
	if report.IsUnsafe {
		gateStatus = "FAILED"
		gateAction = fmt.Sprintf("Halting deployment. Cumulative risk score %d (threshold: %d) or Critical risks identified.", report.RiskScore, report.Threshold)
	}

	policyName := report.PolicyName
	if policyName == "" {
		policyName = "Enterprise Baseline Security Policy"
	}
	policyVersion := report.PolicyVersion
	if policyVersion == "" {
		policyVersion = "1.0"
	}

	return &ReportData{
		Timestamp:             time.Now().UTC(),
		Tool:                  "PlanProof",
		Version:               "1.1.0",
		TargetPlan:            targetPlan,
		PolicyName:            policyName,
		PolicyVersion:         policyVersion,
		GateStatus:            gateStatus,
		IsUnsafe:              report.IsUnsafe,
		GateAction:            gateAction,
		RiskScore:             report.RiskScore,
		Threshold:             report.Threshold,
		TotalChangesEvaluated: report.TotalChanges,
		TotalViolations:       len(report.RuleViolations),
		SeveritySummary:       report.Summary,
		RuleViolations:        report.RuleViolations,
	}
}

// ExportJSON writes a formatted, machine-readable JSON security report to the specified file.
func ExportJSON(data *ReportData, outputPath string) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON report: %w", err)
	}

	if dir := filepath.Dir(outputPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory for report: %w", err)
		}
	}

	if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON report to '%s': %w", outputPath, err)
	}

	return nil
}

// ExportHTML renders and saves a self-contained, enterprise HTML security audit report.
func ExportHTML(data *ReportData, outputPath string) error {
	tmpl, err := template.New("htmlReport").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse HTML report template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to render HTML report: %w", err)
	}

	if dir := filepath.Dir(outputPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory for report: %w", err)
		}
	}

	if err := os.WriteFile(outputPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write HTML report to '%s': %w", outputPath, err)
	}

	return nil
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PlanProof Security Audit & Risk Gate Report - {{.GateStatus}}</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #111827;
      --card-border: rgba(255, 255, 255, 0.08);
      --text-main: #f9fafb;
      --text-muted: #9ca3af;
      --accent-blue: #3b82f6;
      --critical: #ef4444;
      --critical-bg: rgba(239, 68, 68, 0.12);
      --critical-border: rgba(239, 68, 68, 0.35);
      --high: #f97316;
      --high-bg: rgba(249, 115, 22, 0.12);
      --high-border: rgba(249, 115, 22, 0.35);
      --medium: #f59e0b;
      --medium-bg: rgba(245, 158, 11, 0.12);
      --medium-border: rgba(245, 158, 11, 0.35);
      --low: #3b82f6;
      --low-bg: rgba(59, 130, 246, 0.12);
      --low-border: rgba(59, 130, 246, 0.35);
      --success: #10b981;
      --success-bg: rgba(16, 185, 129, 0.12);
      --success-border: rgba(16, 185, 129, 0.35);
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text-main);
      line-height: 1.5;
      padding: 32px 20px;
    }

    .container {
      max-width: 1100px;
      margin: 0 auto;
    }

    /* Header */
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
      padding-bottom: 24px;
      border-bottom: 1px solid var(--card-border);
      margin-bottom: 28px;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .logo-badge {
      width: 44px;
      height: 44px;
      background: linear-gradient(135deg, #2563eb, #7c3aed);
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 4px 14px rgba(37, 99, 235, 0.4);
    }

    .brand-title {
      font-size: 22px;
      font-weight: 700;
      letter-spacing: -0.02em;
      color: #fff;
    }

    .brand-subtitle {
      font-size: 13px;
      color: var(--text-muted);
    }

    .meta-tags {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }

    .tag {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 12px;
      color: var(--text-muted);
    }

    /* Gate Status Banner */
    .gate-banner {
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 32px;
      display: flex;
      align-items: center;
      gap: 20px;
      border-width: 1px;
      border-style: solid;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
    }

    .gate-banner.passed {
      background: linear-gradient(135deg, rgba(16, 185, 129, 0.15), rgba(6, 78, 59, 0.25));
      border-color: var(--success-border);
    }

    .gate-banner.failed {
      background: linear-gradient(135deg, rgba(239, 68, 68, 0.15), rgba(127, 29, 29, 0.25));
      border-color: var(--critical-border);
    }

    .gate-icon {
      width: 56px;
      height: 56px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      font-size: 26px;
    }

    .gate-banner.passed .gate-icon {
      background: var(--success);
      color: #fff;
      box-shadow: 0 0 20px rgba(16, 185, 129, 0.5);
    }

    .gate-banner.failed .gate-icon {
      background: var(--critical);
      color: #fff;
      box-shadow: 0 0 20px rgba(239, 68, 68, 0.5);
    }

    .gate-info h2 {
      font-size: 20px;
      font-weight: 700;
      margin-bottom: 4px;
    }

    .gate-banner.passed .gate-info h2 { color: #34d399; }
    .gate-banner.failed .gate-info h2 { color: #f87171; }

    .gate-info p {
      font-size: 14px;
      color: #d1d5db;
    }

    /* Metrics Grid */
    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 32px;
    }

    .metric-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 18px 20px;
      transition: transform 0.2s ease, border-color 0.2s ease;
    }

    .metric-card:hover {
      border-color: rgba(255, 255, 255, 0.16);
      transform: translateY(-2px);
    }

    .metric-label {
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-bottom: 8px;
    }

    .metric-value {
      font-size: 28px;
      font-weight: 800;
      color: #fff;
      display: flex;
      align-items: baseline;
      gap: 8px;
    }

    .metric-sub {
      font-size: 12px;
      color: var(--text-muted);
      font-weight: 400;
    }

    /* Severity Breakdown */
    .severity-section {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 32px;
    }

    .section-title {
      font-size: 16px;
      font-weight: 700;
      margin-bottom: 18px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .severity-cards {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 14px;
    }

    .sev-card {
      padding: 14px 18px;
      border-radius: 8px;
      border: 1px solid transparent;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .sev-card.critical { background: var(--critical-bg); border-color: var(--critical-border); }
    .sev-card.high     { background: var(--high-bg); border-color: var(--high-border); }
    .sev-card.medium   { background: var(--medium-bg); border-color: var(--medium-border); }
    .sev-card.low      { background: var(--low-bg); border-color: var(--low-border); }

    .sev-name {
      font-weight: 700;
      font-size: 13px;
      letter-spacing: 0.04em;
    }
    .sev-card.critical .sev-name { color: #fca5a5; }
    .sev-card.high .sev-name     { color: #fdba74; }
    .sev-card.medium .sev-name   { color: #fde047; }
    .sev-card.low .sev-name      { color: #93c5fd; }

    .sev-count {
      font-size: 20px;
      font-weight: 800;
      color: #fff;
    }

    /* Violations List */
    .violations-section {
      margin-bottom: 40px;
    }

    .violation-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 22px;
      margin-bottom: 18px;
      transition: border-color 0.2s ease;
    }

    .violation-card:hover {
      border-color: rgba(255, 255, 255, 0.18);
    }

    .v-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 12px;
    }

    .v-title-group {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }

    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0.05em;
      text-transform: uppercase;
    }

    .badge.critical { background: var(--critical); color: #fff; }
    .badge.high     { background: var(--high); color: #fff; }
    .badge.medium   { background: var(--medium); color: #111; }
    .badge.low      { background: var(--low); color: #fff; }

    .rule-id {
      font-family: monospace;
      font-weight: 700;
      color: #93c5fd;
      font-size: 13px;
    }

    .rule-name {
      font-weight: 600;
      font-size: 15px;
      color: #fff;
    }

    .risk-impact {
      font-size: 12px;
      font-weight: 700;
      color: #f87171;
      background: rgba(239, 68, 68, 0.15);
      padding: 4px 10px;
      border-radius: 6px;
      border: 1px solid var(--critical-border);
    }

    .v-meta {
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      font-size: 13px;
      color: var(--text-muted);
      margin-bottom: 14px;
    }

    .v-meta code {
      font-family: monospace;
      color: #e5e7eb;
      background: rgba(255, 255, 255, 0.05);
      padding: 2px 6px;
      border-radius: 4px;
    }

    .v-desc {
      font-size: 14px;
      color: #d1d5db;
      margin-bottom: 14px;
      line-height: 1.6;
    }

    .v-remediation {
      background: rgba(30, 41, 59, 0.7);
      border-left: 3px solid var(--accent-blue);
      border-radius: 6px;
      padding: 12px 16px;
      font-size: 13px;
    }

    .remediation-label {
      font-weight: 700;
      color: #60a5fa;
      margin-bottom: 4px;
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .remediation-text {
      color: #e2e8f0;
      font-family: monospace;
      word-break: break-all;
    }

    /* Zero Violations Hero */
    .safe-hero {
      background: var(--card-bg);
      border: 1px solid var(--success-border);
      border-radius: 12px;
      padding: 48px 24px;
      text-align: center;
    }

    .safe-hero-icon {
      width: 64px;
      height: 64px;
      margin: 0 auto 16px;
      background: var(--success);
      color: #fff;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 32px;
      box-shadow: 0 0 30px rgba(16, 185, 129, 0.4);
    }

    .safe-hero h3 {
      font-size: 18px;
      color: #34d399;
      margin-bottom: 6px;
    }

    .safe-hero p {
      font-size: 14px;
      color: var(--text-muted);
      max-width: 520px;
      margin: 0 auto;
    }

    /* Footer */
    .footer {
      text-align: center;
      padding-top: 24px;
      border-top: 1px solid var(--card-border);
      font-size: 12px;
      color: var(--text-muted);
    }
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <header class="header">
      <div class="brand">
        <div class="logo-badge">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="m9 12 2 2 4-4"/>
          </svg>
        </div>
        <div>
          <h1 class="brand-title">PlanProof Security Report</h1>
          <p class="brand-subtitle">Enterprise IaC Risk Gate & Architectural Guardrail Auditor</p>
        </div>
      </div>
      <div class="meta-tags">
        <div class="tag">Policy: {{.PolicyName}} (v{{.PolicyVersion}})</div>
        <div class="tag">Plan: {{.TargetPlan}}</div>
        <div class="tag">Audit Time: {{.Timestamp.Format "2006-01-02 15:04:05 MST"}}</div>
      </div>
    </header>

    <!-- Gate Status Banner -->
    <section class="gate-banner {{if .IsUnsafe}}failed{{else}}passed{{end}}">
      <div class="gate-icon">
        {{if .IsUnsafe}}✕{{else}}✓{{end}}
      </div>
      <div class="gate-info">
        <h2>GATE STATUS: [{{.GateStatus}}] {{if .IsUnsafe}}UNACCEPTABLE RISK DETECTED{{else}}SAFE TO APPLY{{end}}</h2>
        <p>{{.GateAction}}</p>
      </div>
    </section>

    <!-- Metrics Grid -->
    <section class="metrics-grid">
      <div class="metric-card">
        <div class="metric-label">Calculated Risk Score</div>
        <div class="metric-value">
          {{.RiskScore}}
          <span class="metric-sub">/ {{.Threshold}} threshold</span>
        </div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Gate Threshold</div>
        <div class="metric-value">{{.Threshold}} <span class="metric-sub">pts max</span></div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Plan Resource Changes</div>
        <div class="metric-value">{{.TotalChangesEvaluated}} <span class="metric-sub">evaluated</span></div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Rule Violations</div>
        <div class="metric-value">{{.TotalViolations}} <span class="metric-sub">detected</span></div>
      </div>
    </section>

    <!-- Severity Breakdown -->
    <section class="severity-section">
      <div class="section-title">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>
        Severity Impact Breakdown
      </div>
      <div class="severity-cards">
        <div class="sev-card critical">
          <span class="sev-name">CRITICAL</span>
          <span class="sev-count">{{.SeveritySummary.Critical}}</span>
        </div>
        <div class="sev-card high">
          <span class="sev-name">HIGH</span>
          <span class="sev-count">{{.SeveritySummary.High}}</span>
        </div>
        <div class="sev-card medium">
          <span class="sev-name">MEDIUM</span>
          <span class="sev-count">{{.SeveritySummary.Medium}}</span>
        </div>
        <div class="sev-card low">
          <span class="sev-name">LOW</span>
          <span class="sev-count">{{.SeveritySummary.Low}}</span>
        </div>
      </div>
    </section>

    <!-- Violations Audit Breakdown -->
    <section class="violations-section">
      <div class="section-title">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        Rule Violation Audit Breakdown
      </div>

      {{if .RuleViolations}}
        {{range .RuleViolations}}
        <div class="violation-card">
          <div class="v-header">
            <div class="v-title-group">
              <span class="badge {{if eq .Severity "CRITICAL"}}critical{{else if eq .Severity "HIGH"}}high{{else if eq .Severity "MEDIUM"}}medium{{else}}low{{end}}">{{.Severity}}</span>
              <span class="rule-id">{{.RuleID}}</span>
              <span class="rule-name">{{.RuleName}}</span>
            </div>
            <span class="risk-impact">+{{.RiskScore}} risk pts</span>
          </div>
          <div class="v-meta">
            <span>Resource: <code>{{.ResourceAddress}}</code></span>
            <span>Type: <code>{{.ResourceType}}</code></span>
          </div>
          <p class="v-desc">{{.Description}}</p>
          {{if .Remediation}}
          <div class="v-remediation">
            <div class="remediation-label">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a7 7 0 0 1 7 7c0 2.38-1.19 4.47-3 5.74V17a2 2 0 0 1-2 2h-4a2 2 0 0 1-2-2v-2.26C6.19 13.47 5 11.38 5 9a7 7 0 0 1 7-7z"/><path d="M9 21h6"/></svg>
              Actionable Remediation Guidance
            </div>
            <div class="remediation-text">{{.Remediation}}</div>
          </div>
          {{end}}
        </div>
        {{end}}
      {{else}}
        <div class="safe-hero">
          <div class="safe-hero-icon">✓</div>
          <h3>Zero Violations Detected</h3>
          <p>The analyzed Terraform plan satisfies all architectural security guardrails and state-safety requirements defined in your policy.</p>
        </div>
      {{end}}
    </section>

    <!-- Footer -->
    <footer class="footer">
      Generated automatically by <strong>PlanProof v{{.Version}}</strong> | CI/CD Risk Gate Automation
    </footer>
  </div>
</body>
</html>
`
