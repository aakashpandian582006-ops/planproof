# Security Policy

PlanProof is an infrastructure-as-code (IaC) security and disaster recovery risk gate engine. Because Platform Engineering and DevOps pipelines rely on PlanProof to intercept catastrophic state destruction and enforce enterprise cloud security postures, we treat the security and integrity of this tool with the highest priority.

---

## Supported Versions

Security updates, patches, and vulnerability fixes are actively applied to the following versions of PlanProof:

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

---

## Reporting a Vulnerability

We appreciate the efforts of the global security research community in responsibly disclosing security vulnerabilities.

If you believe you have discovered a vulnerability in PlanProof—including security rule bypasses, parser evasion flaws, denial of service conditions, or arbitrary code execution risks:

1. **Do NOT open a public GitHub issue.**
2. Report the vulnerability privately via **GitHub Security Advisories** on the PlanProof repository:
   - Navigate to the repository's **Security** tab.
   - Click **Report a vulnerability** to open a confidential disclosure report.
3. Alternatively, send an encrypted or direct email to the maintainers at:
   - **`aakashpandian.5.8.2006@gmail.com`**
   - Subject: `[SECURITY] PlanProof Vulnerability Disclosure - <Brief Summary>`

---

## Information to Include in Your Report

To help us triage and resolve the issue quickly, please include:
- A clear description of the vulnerability and its potential security impact.
- Step-by-step reproduction instructions or a minimal reproducible Terraform plan JSON fixture.
- The version or Git commit of PlanProof tested.
- Any proposed remediation, patch, or mitigation strategy.
- Whether you wish to be credited publicly in the release notes upon patch publication.

---

## Vulnerability Handling SLA & Response Process

When a vulnerability report is submitted, the PlanProof maintainers follow this structured response timeline:

1. **Initial Acknowledgment:** Within **24 to 48 hours**, confirming receipt of the disclosure.
2. **Triage & Reproduction:** Within **3 to 5 business days**, validating the issue in our test harnesses and determining severity (CVSS score).
3. **Remediation & Patch Development:** A patch is engineered and validated against regression test suites.
4. **Coordinated Disclosure:** A security advisory and patched release will be published simultaneously, crediting the reporter.

---

## Scope & Security Boundary

### In Scope
- **Rule Engine Bypasses:** Flaws that allow malicious or insecure IaC resource configurations (e.g., open SSH, unencrypted S3 buckets, wildcard IAM privileges) to evade detection.
- **Stateful Destruction Detection Failures:** Scenarios where stateful resource replacements (`destroy`, `delete`) bypass risk gate threshold checks.
- **Parser Evasion & ReDoS/DoS:** Memory exhaustion, CPU spikes, or crashes caused by maliciously structured Terraform plan JSON inputs.
- **Code Execution:** Any flaw in PlanProof binary or dependencies that leads to unexpected code execution in pipeline runners.

### Out of Scope
- Vulnerabilities requiring physical or root-level compromise of the CI runner execution environment.
- Vulnerabilities within Terraform core or third-party cloud provider binaries themselves.
- Violations or findings caused by third-party plugins not maintained in the PlanProof repository.

---

## Safe Harbor Policy

We consider security research conducted under this policy to be:
- Authorized under applicable anti-hacking laws (including CFAA and equivalent regional statutes).
- Exempt from anti-circumvention claims under the DMCA.
- Lawful and helpful to the overall safety of the DevOps ecosystem.

We will not initiate legal action against security researchers who:
- Act in good faith and avoid privacy violations, data destruction, or disruption of services.
- Keep the details of discovered vulnerabilities confidential until the agreed disclosure timeline expires.

Thank you for helping keep PlanProof and its users secure!
