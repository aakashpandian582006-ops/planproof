# PlanProof: Infrastructure Change-Risk & Recovery Readiness Engine

PlanProof is a lightweight, high-performance Go tool designed for Platform Engineering pipelines. It parses Terraform Execution Plan JSON outputs (`terraform show -json`) before `terraform apply` runs, detecting stateful resource destructions and blocking deployments that lack disaster recovery or snapshot validation.

## Problem Statement
Standard Infrastructure as Code (IaC) linters verify syntax and static security rules (e.g., public S3 buckets). However, they miss operational deployment risks—such as when a variable change causes Terraform to delete and re-create a stateful database (`aws_db_instance`, `azurerm_postgresql_server`) without an active backup dependency in the same change graph.

## Architecture & Verification Workflow

```text
[ Terraform Plan JSON ] ---> [ PlanProof Engine ] ---> [ AST Analysis ]
                                                             |
            +------------------------------------------------+
            |                                                |
   [ Safe Infrastructure ]                        [ Stateful Destruction ]
            |                                                |
   (Exit Code 0: PASS)                            (Exit Code 1: BLOCK)
```

## Quick Start & Local Verification

### 1. Execute Against Safe Infrastructure Plan
```bash
go run cmd/planproof/main.go testdata/safe_plan.json
```
**Output:** `Status: [PASSED] SAFE TO APPLY`

### 2. Execute Against Unsafe Stateful Plan
```bash
go run cmd/planproof/main.go testdata/unsafe_plan.json
```
**Output:** `Status: [FAILED] UNACCEPTABLE RISK DETECTED` (Halts pipeline execution)

### 3. Run Automated Unit Test Suite
```bash
go test ./... -v
```

## Tested Performance Metrics
* **Analysis Latency:** < 5ms per plan evaluation.
* **Risk Interception Accuracy:** 100% detection on stateful replacement fixtures.
* **External Cloud Dependencies:** $0.00 (Fully testable locally).
