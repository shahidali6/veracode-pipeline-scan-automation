import json
import os

def generate_html_dashboard(json_path="results.json", output_html="dashboard.html"):
    # 1. Validate if the results file exists
    if not os.path.exists(json_path):
        print(f"[-] Error: Source file '{json_path}' not found.")
        return

    # 2. Read and parse raw JSON artifact
    with open(json_path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print("[-] Error: Failed to parse JSON. File format may be corrupted.")
            return

    # 3. Extract high-level metadata safety blocks
    app_name = data.get("application_name", "Target Application")
    scan_id = data.get("scan_id", "N/A")
    policy_status = data.get("policy_compliance_status", "Calculated Locally")
    
    # Gather structural vulnerability arrays
    findings = data.get("findings", [])
    
    # Calculate operational flaw metrics
    total_flaws = len(findings)
    high_flaws = sum(1 for f in findings if f.get("severity") >= 4)
    med_flaws = sum(1 for f in findings if f.get("severity") == 3)
    low_flaws = sum(1 for f in findings if f.get("severity") <= 2)

    # Contextual status color definitions
    status_badge = "bg-success" if high_flaws == 0 else "bg-danger"
    status_text = "PASSED BUILD GATE" if high_flaws == 0 else "BUILD BLOCKED"

    # 4. Generate optimized, semantic HTML template string
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Veracode SAST Security Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {{ background-color: #f8f9fa; font-family: system-ui, -apple-system, sans-serif; }}
        .metric-card {{ transition: transform 0.2s; }}
        .metric-card:hover {{ transform: translateY(-3px); }}
        pre {{ background-color: #212529; color: #f8f9fa; padding: 10px; border-radius: 4px; font-size: 0.85rem; }}
    </style>
</head>
<body>
    <div class="container my-5">
        <!-- Header Banner Block -->
        <header class="d-flex justify-content-between align-items-center p-4 bg-white border rounded shadow-sm mb-4">
            <div>
                <h1 class="h3 mb-1 fw-bold text-dark">Veracode Pipeline Scan Report</h1>
                <p class="text-muted mb-0 small">App Name: <strong>{app_name}</strong> | Scan ID: <code class="text-secondary">{scan_id}</code></p>
            </div>
            <span class="badge {status_badge} fs-6 px-3 py-2 fw-semibold">{status_text}</span>
        </header>

        <!-- Metric Scoreboard Row -->
        <div class="row g-3 mb-4 text-center">
            <div class="col-6 col-md-3">
                <div class="bg-white p-3 border rounded shadow-sm metric-card">
                    <div class="text-muted small fw-medium">Total Issues</div>
                    <div class="display-6 fw-bold text-dark">{total_flaws}</div>
                </div>
            </div>
            <div class="col-6 col-md-3">
                <div class="bg-white p-3 border rounded shadow-sm metric-card border-start border-danger border-3">
                    <div class="text-muted small fw-medium text-danger">High / Critical</div>
                    <div class="display-6 fw-bold text-danger">{high_flaws}</div>
                </div>
            </div>
            <div class="col-6 col-md-3">
                <div class="bg-white p-3 border rounded shadow-sm metric-card border-start border-warning border-3">
                    <div class="text-muted small fw-medium text-warning">Medium Flaws</div>
                    <div class="display-6 fw-bold text-warning">{med_flaws}</div>
                </div>
            </div>
            <div class="col-6 col-md-3">
                <div class="bg-white p-3 border rounded shadow-sm metric-card border-start border-info border-3">
                    <div class="text-muted small fw-medium text-info">Low / Info</div>
                    <div class="display-6 fw-bold text-info">{low_flaws}</div>
                </div>
            </div>
        </div>

        <!-- Semantic Vulnerabilities Table -->
        <main class="bg-white border rounded shadow-sm p-4">
            <h2 class="h5 fw-bold mb-3 text-dark">Discovered Vulnerability Directory</h2>
            
            {"" if total_flaws > 0 else '<div class="alert alert-success mb-0">🟢 Perfect execution! 0 vulnerabilities detected in this build.</div>'}
            
            {" " if total_flaws == 0 else f'''
            <div class="table-responsive">
                <table class="table table-hover align-middle mb-0">
                    <thead class="table-light">
                        <tr>
                            <th style="width: 15%">Severity</th>
                            <th style="width: 25%">CWE / Vulnerability</th>
                            <th style="width: 40%">Description & Source Context</th>
                            <th style="width: 20%">File Reference</th>
                        </tr>
                    </thead>
                    <tbody>
            '''}
    """

    # 5. Populate structured table rows iteratively
    for flaw in findings:
        severity_num = flaw.get("severity", 0)
        cwe_id = flaw.get("cwe_id", "N/A")
        issue_type = flaw.get("issue_type", "Security Flaw")
        description = flaw.get("display_text", "No context details available.")
        
        # Determine pinpoint file location details
        files_node = flaw.get("files", {})
        source_file = files_node.get("source_file", {})
        file_path = source_file.get("name", "Unknown Binary Resource")
        line_num = source_file.get("line", "N/A")

        # Map internal weights directly to custom UI element alerts
        if severity_num >= 4:
            sev_badge = '<span class="badge bg-danger">High</span>'
        elif severity_num == 3:
            sev_badge = '<span class="badge bg-warning text-dark">Medium</span>'
        else:
            sev_badge = '<span class="badge bg-info text-dark">Low</span>'

        html_content += f"""
                        <tr>
                            <td>{sev_badge}</td>
                            <td>
                                <div class="fw-bold text-dark">{issue_type}</div>
                                <span class="text-muted small font-monospace">CWE-{cwe_id}</span>
                            </td>
                            <td>
                                <p class="mb-1 small text-secondary">{description}</p>
                            </td>
                            <td>
                                <div class="small font-monospace text-truncate" style="max-width: 220px;" title="{file_path}">{file_path}</div>
                                <span class="text-muted min-small">Line: {line_num}</span>
                            </td>
                        </tr>
        """

    # 6. Append structural termination syntax tags
    if total_flaws > 0:
        html_content += """
                    </tbody>
                </table>
            </div>
        """

    html_content += """
        </main>
        
        <footer class="text-center mt-5 text-muted small">
            <p>Automated Pipeline Dashboard Engine | Powered by DevSecOps Reporting Toolchains</p>
        </footer>
    </div>
</body>
</html>
    """

    # 7. Flush buffers and write the final file down to disk
    with open(output_html, "w", encoding="utf-8") as f:
        f.write(html_content)
        
    print(f"[+] Success: Local HTML dashboard generated cleanly at '{output_html}'.")

if __name__ == "__main__":
    generate_html_dashboard()
