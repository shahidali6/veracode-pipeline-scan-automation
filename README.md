# Containerized Veracode SAST Pipeline Scan Automation

Accelerate application security testing by shifting vulnerability remediation cycles directly into containerized CI/CD build runners. This repository provides the core runner execution scripts and automation configurations to execute high-velocity security checks on every pull request.

> 📊 **Full Case Study & Implementation Details:**  
> For an in-depth architectural breakdown, advanced break-build rules, and local environment setups, read the full engineering guide:  
> **[Veracode SAST Pipeline Scan Automation Guide](https://shahidsaddique.com/projects/veracode/veracode-pipeline-scan)**

---

## 🚀 Features

* **Zero Pipeline Latency:** Optimized container footprint bypassing heavy cloud policy evaluation overhead.
* **Inline Break-Build Logic:** Fail pipelines immediately upon discovering high-severity flaws.
* **Remediation Data Loop:** Automatically outputs a structured `results.json` file for tracking.

## 🛠️ Quick Start

### 1. Prerequisite Variables
Ensure the following secrets are available in your pipeline runner environment:
* `VERACODE_API_ID`
* `VERACODE_API_KEY`

### 2. Execution Script
Execute the runner inside your ephemeral build step container:

```bash
# Pull and execute the localized security wrapper
java -jar /opt/veracode/pipeline-scan.jar \
  --api_id "$VERACODE_API_ID" \
  --api_key "$VERACODE_API_KEY" \
  --file "./build/artifacts/app.war" \
  --fail_on_severity "Very High, High"
