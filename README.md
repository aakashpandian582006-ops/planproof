Markdown
# PlanProof: Enterprise IaC Security & Disaster Recovery Risk Gate Engine

[![Go Reference](https://img.shields.io/badge/go-1.21-00ADD8?style=for-the-badge&logo=go)](https://golang.org)
[![Security Policy](https://img.shields.io/badge/security-enforced-red?style=for-the-badge&logo=shield)](SECURITY.md)
[![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen?style=for-the-badge&logo=githubactions)](.github/workflows/risk-gate.yml)

**PlanProof** is a high-performance, enterprise-ready IaC security and disaster recovery analysis engine written in Go. It intercepts Terraform execution plan JSONs (`terraform show -json`) before `terraform apply` runs in CI/CD pipelines, preventing catastrophic stateful deletions, exposed networking, and permissive multi-cloud IAM policies.

---

## 🎯 Key Capabilities

* 🛡️ **Stateful Disaster Recovery Guard:** Intercepts unplanned replacements or deletions of critical stateful resources (`aws_db_instance`, `aws_s3_bucket`, `azure_storage_account`, `google_sql_database`).
* ☁️ **Multi-Cloud Security Rule Suite:**
  * **AWS:** Catches public S3 buckets, missing server-side encryption (SSE), wildcard IAM policies (`Action: *`, `Resource: *`), and open Security Group SSH/RDP ports (`0.0.0.0/0`).
  * **Azure:** Detects exposed Storage Accounts, unencrypted Azure databases, and open Network Security Groups (NSGs).
* ⚙️ **Declarative YAML Policy Engine (`policy.yaml`):** Calibrate team guardrails, fail-safe parameters, severity weights, and pipeline enforcement thresholds dynamically.
* 📊 **SOC Security Dashboard Exporter:** Generates self-contained, dark-mode glassmorphic HTML security dashboards (`scan_report.html`) and machine-readable JSON pipeline artifacts (`scan_report.json`).

---

## 🏗️ Architecture & Verification Workflow

┌──────────────────────────┐
│  Terraform Plan JSON     │
│  (terraform show -json)  │
└────────────┬─────────────┘
│
▼
┌──────────────────────────┐
│  PlanProof Go Engine     │ ◄─── Declarative YAML Guardrails (policy.yaml)
│  (AST & Policy Analysis) │
└────────────┬─────────────┘
├──────────────────────────────────────┐
▼                                      ▼
┌──────────────────────────┐              ┌──────────────────────────┐
│  Gate Result: PASSED     │              │  Gate Result: BLOCKED    │
│  • Exit Code 0           │              │  • Exit Code 1           │
│  • Safe Deployment       │              │  • SOC HTML Report       │
└──────────────────────────┘              │  • Pipeline Halted       │
└──────────────────────────┘


---

## 🚀 Quick Start & CLI Usage

### 1. Build Binary
```bash
make build
# or
go build -o planproof main.go
