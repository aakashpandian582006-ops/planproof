# PlanProof: Enterprise IaC Security & Disaster Recovery Risk Gate Engine

PlanProof is an enterprise-ready, high-performance Go security and risk analysis engine designed for Platform Engineering and CI/CD deployment pipelines. It parses Terraform Execution Plan JSON outputs (`terraform show -json`) prior to `terraform apply`, intercepting catastrophic stateful resource destructions, unencrypted storage, exposed networking, and permissive IAM policies.

---

## Key Capabilities

- **Stateful Disaster Recovery Guard:** Intercepts unplanned replacements or deletions of critical stateful resources (`aws_db_instance`, `aws_s3_bucket`, `aws_dynamodb_table`, `azurerm_postgresql_server`, `google_sql_database_instance`).
- **AWS Security Rule Suite (`pkg/rules`):**
  - **AWS-S3-001 (HIGH):** Flags S3 buckets missing server-side encryption (SSE).
  - **AWS-S3-002 (CRITICAL):** Blocks S3 buckets with public ACLs (`public-read`, `public-read-write`).
  - **AWS-SG-001 (CRITICAL):** Detects Security Groups exposing SSH (port 22) to the open internet (`0.0.0.0/0` or `::/0`).
  - **AWS-SG-002 (HIGH):** Identifies exposed Windows Remote Desktop (RDP port 3389) from `0.0.0.0/0`.
  - **AWS-IAM-001 (CRITICAL / HIGH):** Catches overly permissive wildcard admin policies (`Action: *`, `Resource: *`).
- **Configurable Risk Gate Thresholds:** Calibrate pipeline enforcement thresholds with the `-threshold` flag (default: 50).
- **Clear Severity Level Breakdown:** Reports categorized by `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW` with actionable remediation guidance.

---

## Architecture & Verification Workflow

```text
[ Terraform Plan JSON ] ---> [ PlanProof Engine ] ---> [ Rules & AST Analysis ]
                                                               |
            +--------------------------------------------------+
            |                                                  |
   [ Safe Infrastructure ]                        [ Security / Stateful Risk ]
            |                                                  |
   (Exit Code 0: PASS)                            (Exit Code 1: BLOCK)
```

---

## Quick Start & Makefile Shortcuts

PlanProof includes a root `Makefile` for streamlined development and CI integration:

```bash
# Compile binary to ./planproof
make build

# Run automated test suite across all packages
make test

# Execute risk gate against a compliant production plan
make scan-safe

# Verify that the risk gate halts deployment on an unsafe plan
make scan-unsafe
```

---

## CLI Usage & Options

```bash
# Basic invocation with positional path
./planproof testdata/safe_plan.json

# Using explicit flags and custom risk threshold
./planproof -plan testdata/aws_demo/aws_production_plan.json -threshold 50

# Options
  -plan string
        Path to Terraform Plan JSON file
  -threshold int
        Risk score threshold to halt deployment (default: 50)
```

---

## Security Policy

For vulnerability reporting, SLAs, and safe harbor details, see [SECURITY.md](SECURITY.md).
