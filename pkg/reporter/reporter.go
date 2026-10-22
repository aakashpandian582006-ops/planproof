package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
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
	gateAction := "Deployment approved. All security policies and state-safety gates satisfied."
	if report.IsUnsafe {
		gateStatus = "FAILED"
		gateAction = fmt.Sprintf("Deployment halted. Risk score %d (threshold: %d) or Critical risks identified.", report.RiskScore, report.Threshold)
	}

	policyName := report.PolicyName
	if policyName == "" {
		policyName = "Enterprise Baseline Security Policy"
	}
	policyVersion := report.PolicyVersion
	if policyVersion == "" {
		policyVersion = "1.2"
	}

	return &ReportData{
		Timestamp:             time.Now().UTC(),
		Tool:                  "PlanProof",
		Version:               "1.2.0",
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

// ExportHTML renders and saves a self-contained, SOC Dark-Mode Glassmorphic HTML security dashboard.
func ExportHTML(data *ReportData, outputPath string) error {
	funcMap := template.FuncMap{
		"cloudProvider": func(resourceType string) string {
			if strings.HasPrefix(resourceType, "aws_") {
				return "AWS"
			}
			if strings.HasPrefix(resourceType, "azurerm_") {
				return "Azure"
			}
			if strings.HasPrefix(resourceType, "google_") {
				return "GCP"
			}
			return "Multi-Cloud"
		},
		"jsonPath": func(v rules.Violation) string {
			if strings.HasPrefix(v.RuleID, "STATE") {
				return fmt.Sprintf("resource_changes[address=%q].change.actions", v.ResourceAddress)
			}
			return fmt.Sprintf("resource_changes[address=%q].change.after", v.ResourceAddress)
		},
		"gaugeOffset": func(score, threshold int) int {
			if threshold <= 0 {
				threshold = 50
			}
			pct := float64(score) / float64(threshold)
			if pct > 1.0 {
				pct = 1.0
			}
			// Circumference of r=44 is 2 * pi * 44 = ~276
			return int(276.0 * (1.0 - pct))
		},
		"pct": func(val, total int) int {
			if total <= 0 {
				return 0
			}
			p := (val * 100) / total
			if p > 100 {
				return 100
			}
			return p
		},
	}

	tmpl, err := template.New("socDashboard").Funcs(funcMap).Parse(socDashboardTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse SOC HTML dashboard template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to render SOC HTML dashboard: %w", err)
	}

	if dir := filepath.Dir(outputPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory for report: %w", err)
		}
	}

	if err := os.WriteFile(outputPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write HTML dashboard to '%s': %w", outputPath, err)
	}

	return nil
}

const socDashboardTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PlanProof SOC Security Dashboard | Gate {{.GateStatus}}</title>
  <style>
    :root {
      --bg-dark: #080c14;
      --panel-bg: rgba(17, 24, 39, 0.75);
      --card-bg: rgba(22, 30, 49, 0.65);
      --border: rgba(255, 255, 255, 0.08);
      --border-focus: rgba(99, 102, 241, 0.4);
      --text: #f3f4f6;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --critical: #ef4444;
      --critical-glow: rgba(239, 68, 68, 0.25);
      --high: #f97316;
      --high-glow: rgba(249, 115, 22, 0.25);
      --medium: #f59e0b;
      --medium-glow: rgba(245, 158, 11, 0.25);
      --low: #3b82f6;
      --low-glow: rgba(59, 130, 246, 0.25);
      --passed: #10b981;
      --passed-glow: rgba(16, 185, 129, 0.25);
      --accent: #6366f1;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(circle at 15% 15%, rgba(99, 102, 241, 0.07) 0%, transparent 40%),
        radial-gradient(circle at 85% 85%, rgba(239, 68, 68, 0.05) 0%, transparent 40%);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      line-height: 1.5;
      padding: 28px 20px 48px;
      min-height: 100vh;
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
    }

    /* Top Bar */
    .top-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 24px;
    }

    .brand-wrap {
      display: flex;
      align-items: center;
      gap: 14px;
    }

    .brand-shield {
      width: 44px;
      height: 44px;
      background: linear-gradient(135deg, #3b82f6, #6366f1, #8b5cf6);
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 0 20px rgba(99, 102, 241, 0.35);
    }

    .brand-text h1 {
      font-size: 20px;
      font-weight: 800;
      letter-spacing: -0.02em;
      color: #fff;
    }

    .brand-text p {
      font-size: 12px;
      color: var(--text-muted);
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }

    .telemetry-chips {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }

    .chip {
      background: var(--panel-bg);
      border: 1px solid var(--border);
      backdrop-filter: blur(12px);
      padding: 6px 14px;
      border-radius: 6px;
      font-size: 12px;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .chip-live-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: {{if .IsUnsafe}}var(--critical){{else}}var(--passed){{end}};
      box-shadow: 0 0 8px {{if .IsUnsafe}}var(--critical){{else}}var(--passed){{end}};
    }

    /* Master Banner */
    .master-banner {
      border-radius: 12px;
      padding: 24px 28px;
      margin-bottom: 28px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 20px;
      border: 1px solid;
      backdrop-filter: blur(16px);
      position: relative;
      overflow: hidden;
    }

    .master-banner.passed {
      background: linear-gradient(135deg, rgba(16, 185, 129, 0.12), rgba(6, 78, 59, 0.3));
      border-color: var(--passed);
      box-shadow: 0 8px 30px var(--passed-glow);
    }

    .master-banner.blocked {
      background: linear-gradient(135deg, rgba(239, 68, 68, 0.12), rgba(127, 29, 29, 0.3));
      border-color: var(--critical);
      box-shadow: 0 8px 30px var(--critical-glow);
    }

    .banner-main {
      display: flex;
      align-items: center;
      gap: 18px;
    }

    .banner-icon {
      width: 58px;
      height: 58px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 28px;
      font-weight: 800;
      flex-shrink: 0;
    }

    .master-banner.passed .banner-icon {
      background: var(--passed);
      color: #fff;
      box-shadow: 0 0 25px var(--passed);
    }

    .master-banner.blocked .banner-icon {
      background: var(--critical);
      color: #fff;
      box-shadow: 0 0 25px var(--critical);
    }

    .banner-content h2 {
      font-size: 22px;
      font-weight: 800;
      letter-spacing: -0.01em;
      margin-bottom: 4px;
    }

    .master-banner.passed .banner-content h2 { color: #34d399; }
    .master-banner.blocked .banner-content h2 { color: #f87171; }

    .banner-content p {
      font-size: 14px;
      color: #cbd5e1;
    }

    .banner-meta {
      text-align: right;
    }

    .banner-status-pill {
      display: inline-block;
      padding: 6px 14px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 800;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      margin-bottom: 6px;
    }

    .master-banner.passed .banner-status-pill {
      background: rgba(16, 185, 129, 0.25);
      color: #34d399;
      border: 1px solid var(--passed);
    }

    .master-banner.blocked .banner-status-pill {
      background: rgba(239, 68, 68, 0.25);
      color: #f87171;
      border: 1px solid var(--critical);
    }

    /* Grid Layout */
    .dashboard-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 18px;
      margin-bottom: 28px;
    }

    .card {
      background: var(--panel-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      backdrop-filter: blur(12px);
      transition: transform 0.2s ease, border-color 0.2s ease;
    }

    .card:hover {
      border-color: rgba(255, 255, 255, 0.15);
      transform: translateY(-2px);
    }

    .card-title {
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      color: var(--text-dim);
      margin-bottom: 12px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    /* Gauge Card */
    .gauge-wrap {
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .gauge-svg {
      width: 90px;
      height: 90px;
      transform: rotate(-90deg);
    }

    .gauge-circle-bg {
      fill: none;
      stroke: rgba(255, 255, 255, 0.06);
      stroke-width: 8;
    }

    .gauge-circle-progress {
      fill: none;
      stroke-width: 8;
      stroke-linecap: round;
      stroke-dasharray: 276;
      stroke-dashoffset: {{gaugeOffset .RiskScore .Threshold}};
      stroke: {{if .IsUnsafe}}var(--critical){{else}}var(--passed){{end}};
      transition: stroke-dashoffset 0.8s ease-in-out;
    }

    .gauge-text {
      flex: 1;
    }

    .gauge-score {
      font-size: 32px;
      font-weight: 900;
      color: #fff;
      line-height: 1;
      margin-bottom: 4px;
    }

    .gauge-sub {
      font-size: 13px;
      color: var(--text-muted);
    }

    /* Severity Breakdown Bar */
    .sev-bar-wrap {
      margin-bottom: 16px;
    }

    .sev-progress-bar {
      height: 10px;
      border-radius: 6px;
      background: rgba(255, 255, 255, 0.06);
      display: flex;
      overflow: hidden;
      margin-bottom: 12px;
    }

    .sev-seg-critical { background: var(--critical); }
    .sev-seg-high     { background: var(--high); }
    .sev-seg-medium   { background: var(--medium); }
    .sev-seg-low      { background: var(--low); }

    .sev-pills {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 8px;
    }

    .sev-pill {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 6px 10px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 12px;
    }

    .sev-pill.crit { border-left: 3px solid var(--critical); color: #fca5a5; }
    .sev-pill.hi   { border-left: 3px solid var(--high); color: #fdba74; }
    .sev-pill.med  { border-left: 3px solid var(--medium); color: #fde047; }
    .sev-pill.lo   { border-left: 3px solid var(--low); color: #93c5fd; }

    .sev-pill-count {
      font-weight: 800;
      color: #fff;
    }

    /* Search & Filter Bar */
    .filter-bar {
      background: var(--panel-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px 18px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 22px;
    }

    .search-input {
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 8px 14px;
      color: #fff;
      font-size: 13px;
      min-width: 280px;
      outline: none;
      transition: border-color 0.2s ease;
    }

    .search-input:focus {
      border-color: var(--accent);
    }

    .filter-tabs {
      display: flex;
      gap: 6px;
    }

    .tab-btn {
      background: transparent;
      border: 1px solid var(--border);
      color: var(--text-muted);
      border-radius: 6px;
      padding: 6px 12px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .tab-btn:hover, .tab-btn.active {
      background: var(--accent);
      color: #fff;
      border-color: var(--accent);
    }

    /* Collapsible Violation Cards */
    .violations-wrap {
      margin-bottom: 36px;
    }

    .soc-violation-card {
      background: var(--panel-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      margin-bottom: 14px;
      overflow: hidden;
      transition: border-color 0.2s ease;
    }

    .soc-violation-card:hover {
      border-color: rgba(255, 255, 255, 0.18);
    }

    .v-header-btn {
      width: 100%;
      background: transparent;
      border: none;
      padding: 16px 20px;
      text-align: left;
      cursor: pointer;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      color: inherit;
    }

    .v-title-meta {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }

    .badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 5px;
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0.05em;
      text-transform: uppercase;
    }

    .badge.critical { background: var(--critical); color: #fff; }
    .badge.high     { background: var(--high); color: #fff; }
    .badge.medium   { background: var(--medium); color: #111; }
    .badge.low      { background: var(--low); color: #fff; }

    .cloud-pill {
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid var(--border);
      padding: 2px 7px;
      border-radius: 4px;
      font-size: 11px;
      color: #94a3b8;
      font-weight: 600;
    }

    .rule-id-text {
      font-family: monospace;
      color: #93c5fd;
      font-size: 13px;
      font-weight: 700;
    }

    .rule-name-text {
      color: #f1f5f9;
      font-weight: 600;
      font-size: 14px;
    }

    .risk-impact-pill {
      font-size: 12px;
      font-weight: 800;
      color: #f87171;
      background: rgba(239, 68, 68, 0.15);
      padding: 4px 10px;
      border-radius: 6px;
      border: 1px solid rgba(239, 68, 68, 0.3);
    }

    .v-body {
      padding: 0 20px 20px;
      border-top: 1px solid rgba(255, 255, 255, 0.04);
      margin-top: 4px;
    }

    .json-path-box {
      background: rgba(0, 0, 0, 0.35);
      border: 1px solid rgba(255, 255, 255, 0.06);
      border-radius: 6px;
      padding: 8px 12px;
      margin: 12px 0;
      font-family: monospace;
      font-size: 12px;
      color: #e2e8f0;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .json-path-label {
      color: var(--text-dim);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .v-desc-text {
      font-size: 13px;
      color: #cbd5e1;
      margin-bottom: 14px;
      line-height: 1.6;
    }

    .remediation-block {
      background: rgba(15, 23, 42, 0.85);
      border-left: 3px solid var(--accent);
      border-radius: 6px;
      padding: 12px 16px;
      position: relative;
    }

    .remediation-head {
      font-size: 12px;
      font-weight: 700;
      color: #818cf8;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 6px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .copy-btn {
      background: rgba(255, 255, 255, 0.08);
      border: 1px solid var(--border);
      color: #cbd5e1;
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 11px;
      cursor: pointer;
      transition: background 0.2s ease;
    }

    .copy-btn:hover {
      background: rgba(255, 255, 255, 0.16);
    }

    .remediation-code {
      font-family: monospace;
      font-size: 13px;
      color: #e2e8f0;
      word-break: break-all;
    }

    /* Compliant Zero-State */
    .zero-state {
      background: var(--panel-bg);
      border: 1px solid var(--passed);
      border-radius: 12px;
      padding: 48px 24px;
      text-align: center;
      backdrop-filter: blur(12px);
    }

    .zero-shield {
      width: 64px;
      height: 64px;
      border-radius: 50%;
      background: var(--passed);
      color: #fff;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 32px;
      margin: 0 auto 16px;
      box-shadow: 0 0 30px var(--passed-glow);
    }

    .zero-state h3 {
      font-size: 18px;
      color: #34d399;
      margin-bottom: 6px;
      font-weight: 800;
    }

    .zero-state p {
      font-size: 14px;
      color: var(--text-muted);
      max-width: 500px;
      margin: 0 auto;
    }

    /* Footer */
    .soc-footer {
      text-align: center;
      padding-top: 24px;
      border-top: 1px solid var(--border);
      font-size: 12px;
      color: var(--text-dim);
    }
  </style>
</head>
<body>
  <div class="container">
    <!-- Top Bar -->
    <header class="top-bar">
      <div class="brand-wrap">
        <div class="brand-shield">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="m9 12 2 2 4-4"/>
          </svg>
        </div>
        <div class="brand-text">
          <h1>PLANPROOF // SOC SECURITY OPERATIONS</h1>
          <p>Multi-Cloud IaC Policy Engine & Risk Gate</p>
        </div>
      </div>
      <div class="telemetry-chips">
        <div class="chip">
          <span class="chip-live-dot"></span>
          Gate: <strong>{{.GateStatus}}</strong>
        </div>
        <div class="chip">Policy: {{.PolicyName}} (v{{.PolicyVersion}})</div>
        <div class="chip">Audited: {{.Timestamp.Format "2006-01-02 15:04:05 UTC"}}</div>
      </div>
    </header>

    <!-- Master Gate Banner -->
    <section class="master-banner {{if .IsUnsafe}}blocked{{else}}passed{{end}}">
      <div class="banner-main">
        <div class="banner-icon">{{if .IsUnsafe}}✕{{else}}✓{{end}}</div>
        <div class="banner-content">
          <h2>GATE STATUS: [{{.GateStatus}}] {{if .IsUnsafe}}DEPLOYMENT BLOCKED (UNACCEPTABLE RISK){{else}}DEPLOYMENT APPROVED (SAFE TO APPLY){{end}}</h2>
          <p>{{.GateAction}}</p>
        </div>
      </div>
      <div class="banner-meta">
        <div class="banner-status-pill">{{.GateStatus}}</div>
        <div style="font-size: 12px; color: #94a3b8;">Plan: {{.TargetPlan}}</div>
      </div>
    </section>

    <!-- Metrics Grid -->
    <section class="dashboard-grid">
      <!-- 1. Risk Gauge -->
      <div class="card">
        <div class="card-title">
          <span>Cumulative Risk Score</span>
          <span>Threshold: {{.Threshold}}</span>
        </div>
        <div class="gauge-wrap">
          <svg class="gauge-svg" viewBox="0 0 100 100">
            <circle class="gauge-circle-bg" cx="50" cy="50" r="44"/>
            <circle class="gauge-circle-progress" cx="50" cy="50" r="44"/>
          </svg>
          <div class="gauge-text">
            <div class="gauge-score">{{.RiskScore}}</div>
            <div class="gauge-sub">/ {{.Threshold}} max risk pts</div>
          </div>
        </div>
      </div>

      <!-- 2. Severity Breakdown -->
      <div class="card">
        <div class="card-title">
          <span>Severity Distribution</span>
          <span>{{.TotalViolations}} total</span>
        </div>
        <div class="sev-bar-wrap">
          <div class="sev-progress-bar">
            {{$tot := .TotalViolations}}
            {{if gt .SeveritySummary.Critical 0}}<div class="sev-seg-critical" style="width: {{pct .SeveritySummary.Critical $tot}}%;"></div>{{end}}
            {{if gt .SeveritySummary.High 0}}<div class="sev-seg-high" style="width: {{pct .SeveritySummary.High $tot}}%;"></div>{{end}}
            {{if gt .SeveritySummary.Medium 0}}<div class="sev-seg-medium" style="width: {{pct .SeveritySummary.Medium $tot}}%;"></div>{{end}}
            {{if gt .SeveritySummary.Low 0}}<div class="sev-seg-low" style="width: {{pct .SeveritySummary.Low $tot}}%;"></div>{{end}}
          </div>
          <div class="sev-pills">
            <div class="sev-pill crit">
              <span>CRITICAL</span>
              <span class="sev-pill-count">{{.SeveritySummary.Critical}}</span>
            </div>
            <div class="sev-pill hi">
              <span>HIGH</span>
              <span class="sev-pill-count">{{.SeveritySummary.High}}</span>
            </div>
            <div class="sev-pill med">
              <span>MEDIUM</span>
              <span class="sev-pill-count">{{.SeveritySummary.Medium}}</span>
            </div>
            <div class="sev-pill lo">
              <span>LOW</span>
              <span class="sev-pill-count">{{.SeveritySummary.Low}}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- 3. Resource Changes Audited -->
      <div class="card">
        <div class="card-title">
          <span>Resources Scanned</span>
          <span>IaC Scope</span>
        </div>
        <div style="font-size: 32px; font-weight: 900; color: #fff; margin-bottom: 4px;">
          {{.TotalChangesEvaluated}}
        </div>
        <div style="font-size: 13px; color: var(--text-muted);">Resource change blocks parsed from execution plan.</div>
      </div>

      <!-- 4. Gate Policy Target -->
      <div class="card">
        <div class="card-title">
          <span>Policy Enforcement</span>
          <span>SOC Active</span>
        </div>
        <div style="font-size: 14px; font-weight: 700; color: #fff; margin-bottom: 4px;">
          {{.PolicyName}}
        </div>
        <div style="font-size: 13px; color: var(--text-muted);">
          Zero-tolerance on CRITICAL risks; threshold cut-off at {{.Threshold}} points.
        </div>
      </div>
    </section>

    <!-- Search & Filter Controls -->
    <div class="filter-bar">
      <input type="text" id="searchInput" class="search-input" placeholder="Search by rule ID, resource address, or cloud provider..." onkeyup="filterViolations()">
      <div class="filter-tabs">
        <button class="tab-btn active" onclick="setSeverityFilter('ALL', this)">ALL ({{.TotalViolations}})</button>
        <button class="tab-btn" onclick="setSeverityFilter('CRITICAL', this)">CRITICAL ({{.SeveritySummary.Critical}})</button>
        <button class="tab-btn" onclick="setSeverityFilter('HIGH', this)">HIGH ({{.SeveritySummary.High}})</button>
        <button class="tab-btn" onclick="setSeverityFilter('MEDIUM', this)">MEDIUM ({{.SeveritySummary.Medium}})</button>
        <button class="tab-btn" onclick="setSeverityFilter('LOW', this)">LOW ({{.SeveritySummary.Low}})</button>
      </div>
    </div>

    <!-- Violations List -->
    <section class="violations-wrap">
      {{if .RuleViolations}}
        {{range .RuleViolations}}
        <div class="soc-violation-card violation-item" data-severity="{{.Severity}}" data-search="{{.RuleID}} {{.ResourceAddress}} {{.ResourceType}} {{cloudProvider .ResourceType}}">
          <button class="v-header-btn" onclick="toggleCard(this)">
            <div class="v-title-meta">
              <span class="badge {{if eq .Severity "CRITICAL"}}critical{{else if eq .Severity "HIGH"}}high{{else if eq .Severity "MEDIUM"}}medium{{else}}low{{end}}">{{.Severity}}</span>
              <span class="cloud-pill">{{cloudProvider .ResourceType}}</span>
              <span class="rule-id-text">{{.RuleID}}</span>
              <span class="rule-name-text">{{.RuleName}}</span>
            </div>
            <span class="risk-impact-pill">+{{.RiskScore}} pts</span>
          </button>
          <div class="v-body">
            <div class="json-path-box">
              <div>
                <span class="json-path-label">Target AST JSON Path: </span>
                <code>{{jsonPath .}}</code>
              </div>
              <span class="cloud-pill">{{.ResourceType}}</span>
            </div>
            <p class="v-desc-text">{{.Description}}</p>
            {{if .Remediation}}
            <div class="remediation-block">
              <div class="remediation-head">
                <span>Actionable Remediation Guidance</span>
                <button class="copy-btn" onclick="copyRemediation(this)">Copy Snippet</button>
              </div>
              <div class="remediation-code">{{.Remediation}}</div>
            </div>
            {{end}}
          </div>
        </div>
        {{end}}
      {{else}}
        <div class="zero-state">
          <div class="zero-shield">✓</div>
          <h3>Zero Violations Detected</h3>
          <p>Every resource change defined in this Terraform execution plan complies with all organizational security policies and stateful disaster recovery standards.</p>
        </div>
      {{end}}
    </section>

    <!-- Footer -->
    <footer class="soc-footer">
      Generated by <strong>PlanProof v{{.Version}}</strong> | Enterprise IaC Security Engine & Automated Pipeline Gate
    </footer>
  </div>

  <script>
    let activeSeverity = 'ALL';

    function setSeverityFilter(sev, btn) {
      activeSeverity = sev;
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      filterViolations();
    }

    function filterViolations() {
      const query = document.getElementById('searchInput').value.toLowerCase();
      const items = document.querySelectorAll('.violation-item');

      items.forEach(item => {
        const itemSev = item.getAttribute('data-severity');
        const itemSearch = item.getAttribute('data-search').toLowerCase();

        const matchesSev = (activeSeverity === 'ALL' || itemSev === activeSeverity);
        const matchesQuery = itemSearch.includes(query);

        if (matchesSev && matchesQuery) {
          item.style.display = 'block';
        } else {
          item.style.display = 'none';
        }
      });
    }

    function toggleCard(btn) {
      const body = btn.nextElementSibling;
      if (body.style.display === 'none') {
        body.style.display = 'block';
      } else {
        body.style.display = 'none';
      }
    }

    function copyRemediation(btn) {
      const code = btn.closest('.remediation-block').querySelector('.remediation-code').innerText;
      navigator.clipboard.writeText(code).then(() => {
        const orig = btn.innerText;
        btn.innerText = 'Copied!';
        setTimeout(() => { btn.innerText = orig; }, 1500);
      });
    }
  </script>
</body>
</html>
`
