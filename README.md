# PlanProof: Enterprise IaC Security & Disaster Recovery Risk Gate Engine

PlanProof is an enterprise-grade, high-performance Go security and risk analysis engine designed for Platform Engineering and CI/CD deployment pipelines. It parses Terraform Execution Plan JSON outputs (`terraform show -json`) prior to `terraform apply`, intercepting catastrophic stateful resource destructions, unencrypted storage, exposed networking, and permissive IAM policies.

---

## Key Capabilities

- **Custom Policy Configuration (YAML):** Fine-tune risk thresholds, failure triggers (`fail_on_critical`, `fail_on_high`), severity risk point weights, and toggle or override individual rules via `policy.yaml` or custom config files with `-config`.
- **Advanced HTML & JSON Reporting:**
  - **Executive HTML Reports (`-output-html`):** Dark-mode, glassmorphic security audit dashboard showing real-time gate status badges, severity impact breakdowns, cumulative risk score meters, and actionable remediation guidance.
  - **Structured JSON Integration (`-output-json`):** Machine-readable schema tailored for CI/CD quality gate enforcement, SIEM ingestion, and automated artifact archiving.
- **Stateful Disaster Recovery Guard:** Intercepts unplanned replacements or deletions of critical stateful resources (`aws_db_instance`, `aws_s3_bucket`, `aws_dynamodb_table`, `azurerm_postgresql_server`, `google_sql_database_instance`).
- **AWS Security Rule Suite (`pkg/rules`):**
  - **STATE-001 (CRITICAL):** Guards stateful resources against unvalidated destruction or accidental replacement.
  - **AWS-S3-001 (HIGH):** Flags S3 buckets missing server-side encryption (SSE).
  - **AWS-S3-002 (CRITICAL):** Blocks S3 buckets with public ACLs (`public-read`, `public-read-write`, `website`).
  - **AWS-SG-001 (CRITICAL):** Detects Security Groups exposing SSH (port 22) to the open internet (`0.0.0.0/0` or `::/0`).
  - **AWS-SG-002 (HIGH):** Identifies exposed Windows Remote Desktop (RDP port 3389) from `0.0.0.0/0`.
  - **AWS-IAM-001 (CRITICAL):** Catches overly permissive wildcard admin policies (`Action: *`, `Resource: *`).
- **Configurable Risk Gate Thresholds:** Calibrate pipeline enforcement thresholds with the `-threshold` flag (default: 50).

---

## Architecture & Verification Workflow

```text
[ Terraform Plan JSON ] ---> [ PlanProof Engine ] ---> [ YAML Policy & AST Rules ]
                                                                |
            +---------------------------------------------------+
            |                                                   |
   [ Safe Infrastructure ]                         [ Security / Stateful Risk ]
            |                                                   |
   (Exit Code 0: PASS)                             (Exit Code 1: BLOCK)
   + HTML / JSON Report                            + HTML / JSON Report
```

---

## Quick Start & Makefile Shortcuts

PlanProof includes a root `Makefile` for streamlined development, local audits, and CI integration:

```bash
# Compile binary to ./planproof
make build

# Run automated test suite across all packages (analyzer, config, reporter, rules)
make test

# Execute risk gate against a compliant production plan
make scan-safe

# Verify that the risk gate halts deployment on an unsafe plan
make scan-unsafe

# Generate an executive HTML security report (report.html)
make scan-html

# Export a structured JSON report (report.json) for CI/CD integration
make scan-json

# Clean up binaries and generated test reports
make clean
```

---

## CLI Usage & Options

```bash
# Basic invocation with positional plan path
./planproof testdata/safe_plan.json

# Using a custom YAML policy configuration
./planproof -plan testdata/aws_demo/aws_production_plan.json -config policy.yaml

# Generating both HTML and JSON reports simultaneously
./planproof -plan testdata/aws_demo/aws_unsafe_plan.json \
  -config policy.yaml \
  -output-html report.html \
  -output-json report.json

# Options Reference:
  -plan string
        Path to Terraform Plan JSON file (or positional argument)
  -config string
        Path to YAML policy config file (e.g. policy.yaml, default: auto-detects ./policy.yaml)
  -threshold int
        Risk score threshold to halt deployment (default: 50, overrides policy threshold)
  -output-html string
        Path to export self-contained HTML security report (e.g. report.html)
  -output-json string
        Path to export structured JSON security report (e.g. report.json)
```

---

## YAML Policy Configuration (`policy.yaml`)

PlanProof supports declaring organizational guardrails via declarative YAML:

```yaml
version: "1.0"
name: "Enterprise Baseline Security Policy"

gate:
  threshold: 50           # Deployment halts if overall risk score >= threshold
  fail_on_critical: true  # Always halt if 1 or more CRITICAL violations are found
  fail_on_high: false     # Strictly halt if any HIGH violation is found

severity_weights:
  critical: 50
  high: 25
  medium: 15
  low: 5

rules:
  STATE-001:
    enabled: true
    severity: "CRITICAL"
    risk_score: 50

  AWS-S3-001:
    enabled: true
    severity: "HIGH"
    risk_score: 25

  AWS-SG-001:
    enabled: true
    severity: "CRITICAL"
    risk_score: 50
```

---

## Security Policy

For vulnerability reporting, SLAs, and safe harbor details, see [SECURITY.md](SECURITY.md).
