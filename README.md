<div align="center">

# 🛡️ PLANPROOF: ENTERPRISE IaC SECURITY & DISASTER RECOVERY RISK GATE

### ⚡ *Automated AST Static Analysis & Shift-Left Infrastructure-as-Code Policy Engine for Multi-Cloud Pipelines* ⚡

[![Go Reference](https://img.shields.io/badge/Go-1.21-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev/)
[![Security Enforced](https://img.shields.io/badge/Security-Enforced_SOC2-red?style=for-the-badge&logo=armorsmith&logoColor=white)](https://github.com/aakashpandian582006-ops/planproof)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge&logo=githubactions&logoColor=white)](https://github.com/aakashpandian582006-ops/planproof/actions)
[![License MIT](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

---

### 🌐 **LIVE ENTERPRISE DEMO MATRIX**
| Resource Hub | Live Link / File Access | Purpose & Technical Utility |
| :--- | :--- | :--- |
| 📊 **Interactive SOC Security Dashboard** | [**🚀 Open Live Security Report**](https://aakashpandian582006-ops.github.io/planproof/) | Live Dark-Mode Glassmorphic Audit Gate & Risk Exporter |
| 🛡️ **Declarative Policy Engine** | [`policy.yaml`](policy.yaml) | YAML Severity Weights, Guardrails & Disaster Thresholds |
| ⚡ **Automated CI/CD Pipeline Gate** | [`.github/workflows`](.github/workflows) | Shift-Left Security Pipeline & GitHub Actions Automation |

---

</div>

## 📌 1. EXECUTIVE SUMMARY & ARCHITECTURAL OVERVIEW

**PlanProof** is a high-performance, enterprise-grade Infrastructure-as-Code (IaC) security static analysis engine written in **Go**. Designed for high-scale Cloud Operations and DevSecOps teams, PlanProof acts as an uncompromised **Risk Gate** inside CI/CD pipelines.

It intercepts Terraform execution plan JSONs (`terraform show -json`) *before* `terraform apply` executes on production infrastructure. By parsing the Abstract Syntax Tree (AST) of the plan, PlanProof calculates weighted risk scores, blocks catastrophic stateful deletions, and validates zero-trust multi-cloud policies across **AWS**, **Azure**, and **GCP**.

> 💡 **Why PlanProof is Different:** Unlike generic linters, PlanProof features an explicit **Stateful Disaster Recovery Guard** specifically tuned to prevent accidental database or storage liquidations, returning an automated **`Exit Code 1`** to halt unsafe deployments immediately.

---

## 🏗️ 2. SYSTEM ARCHITECTURE & VERIFICATION FLOW

```mermaid
graph TD
    A[📂 Terraform Plan JSON] -->|terraform show -json| B(⚡ PlanProof Go Security Engine)
    C[🛡️ Declarative Rules: policy.yaml] -->|AST Policy Analysis| B
    
    B --> D{🚨 Risk Gate Evaluation}
    
    D -->|✅ PASS: Risk Score < Threshold| E[🟢 Exit Code 0: Safe Deployment Allowed]
    D -->|🛑 FAIL: Stateful Deletion / High Severity| F[🔴 Exit Code 1: Pipeline Halted]
    
    E --> G[📊 Generate Glassmorphic SOC HTML Dashboard]
    F --> G
    G --> H[📁 Export Machine-Readable JSON Artifacts]