# 🏥 Healthcare Code Security Scanner

A production-grade, multi-language security assessment tool designed specifically for healthcare applications. This scanner identifies vulnerabilities, maps them to **HIPAA Security Rule** sections, provides automated remediation code, and generates audit-ready reports.

Built with **Semgrep**, **Python**, and **Flask**, it integrates seamlessly into CI/CD pipelines and offers a real-time web dashboard for security monitoring.

---

## ✨ Key Features

- **🛡️ Multi-Language Support**: Scans Python, Java, C#, JavaScript, and TypeScript.
- **📜 HIPAA Compliance Mapping**: Every finding is mapped to specific HIPAA sections (e.g., §164.312, §164.308).
- **🔧 Automated Remediation**: Provides step-by-step fix instructions and "Before/After" code examples.
- **📊 Real-Time Dashboard**: Visualizes findings, risk scores, and compliance status via a web UI.
- **🔄 CI/CD Integration**: GitHub Actions workflow to block merges on critical vulnerabilities.
- **📄 Audit-Ready Reports**: Generates professional PDF and Word reports with full context.
- **☁️ Cloud & Local Scanning**: Scans local directories or clones and scans public/private GitHub repositories.

---

## 📋 Prerequisites

- **Python 3.10+**
- **Git**
- **Semgrep CLI** (Installed via `pip`)
- **PowerShell 5.1+** (Windows) or **Bash** (Linux/macOS)

---

## 🚀 Installation & Configuration

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/healthcare-security-scanner.git
cd healthcare-security-scanner

2. Install Dependencies

pip install semgrep python-docx reportlab PyGithub flask plotly

3. Verify Installation

Run the test script to ensure everything is working:

# Windows
.\test-ci.ps1

# Linux/macOS
chmod +x test-ci.sh && ./test-ci.sh

📖 Usage Guide
1. Scan a Local Directory

Scan your current project for vulnerabilities:

python scanner.py . --output my_project_report --format both

Outputs: my_project_report.docx and my_project_report.pdf
2. Scan a GitHub Repository

Scan an external repository (e.g., a dependency or legacy codebase):

# Public Repo
python scanner.py "https://github.com/juice-shop/juice-shop" --output juice_scan --format both

# Private Repo (requires token)
python scanner.py "https://github.com/org/private-repo" --output private_scan --format both --github-token YOUR_TOKEN

3. View the Web Dashboard

Launch the visualization dashboard to see findings in real-time:

python dashboard.py

Open your browser to: http://localhost:5000
4. Run in CI/CD (GitHub Actions)

The .github/workflows/security-scan.yml file is pre-configured.

    Triggers: On every push and pull_request.
    Behavior:
        Scans code automatically.
        Posts findings as PR comments.
        Blocks merge if Critical vulnerabilities are found.
        Uploads reports as artifacts.

🛠️ Maintenance & Customization
Updating Security Rules (healthcare_rules.yaml)

To add new detection patterns or update existing ones:

    Edit the file: Open healthcare_rules.yaml.
    Add a Rule: Follow the existing structure.

    - id: my-new-rule
      pattern-regex: 'your-pattern-here'
      languages: [python, java]
      severity: ERROR
      message: "Description of the issue."
      metadata:
        category: security
        cwe: CWE-XXX
        impact: "High: Data exposure"
        hipaa_reference: "§164.312(e)(1)"
        remediation_priority: "Immediate"
        max_remediation_days: 7

    Validate: Run semgrep validate healthcare_rules.yaml to check for syntax errors.
    Commit: git add healthcare_rules.yaml && git commit -m "feat: Add new security rule"

Expanding Remediation Templates (remediations.py)

To provide better fix guidance for new rules:

    Edit the file: Open remediations.py.
    Add a Template: Add a new entry to the REMEDIATION_TEMPLATES dictionary using the rule ID.

    "my-new-rule": {
        "title": "Fix My New Rule",
        "description": "Detailed explanation of the vulnerability.",
        "steps": [
            "Step 1: Identify the issue.",
            "Step 2: Apply the fix."
        ],
        "before": '''# Bad code example''',
        "after": '''# Good code example''',
        "resources": [
            ("Link Title", "https://example.com")
        ],
        "severity_impact": "High: Data exposure"
    }

    Test: Run a scan to ensure the new remediation appears in the report.

Adding New Languages

To support a new language (e.g., Go, Ruby):

    Add Rules: Define patterns in healthcare_rules.yaml with languages: [go].
    Add Remediations: Create a template in remediations.py for the new rule IDs.
    Update Dashboard: Modify dashboard.py to parse and display findings for the new language.

📂 Project Structure

.
├── .github/
│   └── workflows/
│       └── security-scan.yml   # CI/CD pipeline
├── docs/
│   └── SECURITY_GUIDELINES.md  # Best practices
├── templates/
│   └── dashboard.html          # Web dashboard UI
├── healthcare_rules.yaml       # Semgrep detection rules
├── remediations.py             # Remediation templates & code fixes
├── scanner.py                  # Main scanning engine
├── dashboard.py                # Flask web dashboard
├── test-ci.ps1                 # Local testing script (Windows)
├── requirements.txt            # Python dependencies
└── README.md                   # This file

📊 Report Output Example

The generated reports include:

    Executive Summary: Total findings and risk score.
    HIPAA Compliance Overview: Table mapping findings to regulations.
    Remediation Timeline: Deadlines based on severity.
    Detailed Findings:
        File & Line number.
        Severity & Impact.
        Before/After Code Snippets.
        Step-by-step fix instructions.
        External resource links.

🤝 Contributing

    Fork the repository.
    Create a feature branch (git checkout -b feature/new-rule).
    Commit your changes (git commit -m 'Add new rule').
    Push to the branch (git push origin feature/new-rule).
    Open a Pull Request.

📄 License

This project is licensed under the MIT License. See LICENSE for details.
