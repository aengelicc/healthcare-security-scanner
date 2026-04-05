#!/usr/bin/env python3
"""
Healthcare Code Security Scanner
Generates PDF/Word reports from Semgrep findings
Supports local directories AND GitHub repositories
Includes HIPAA Compliance Mapping and Automated Remediation
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Import remediation templates
try:
    from remediations import generate_remediation_section, get_remediation

    HAS_REMEDIATIONS = True
except ImportError:
    HAS_REMEDIATIONS = False
    print("Warning: remediations.py not found. Install remediation templates.")

try:
    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.shared import Inches, Pt, RGBColor

    HAS_DOCX = True
except ImportError:
    HAS_DOCX = False
    print("Warning: python-docx not installed. Install with: pip install python-docx")

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False
    print("Warning: reportlab not installed. Install with: pip install reportlab")

try:
    from github import Github

    HAS_GITHUB = True
except ImportError:
    HAS_GITHUB = False
    print("Warning: PyGithub not installed. Install with: pip install PyGithub")


class SecurityScanner:
    def __init__(self, rules_file: str = "healthcare_rules.yaml"):
        self.rules_file = rules_file
        self.findings: List[Dict[str, Any]] = []
        self.scan_metadata: Dict[str, Any] = {}
        self.repo_info: Dict[str, Any] = {}

    def run_semgrep(self, target_path: str, output_format: str = "json") -> bool:
        """Execute Semgrep scan and capture results via temp file"""
        try:
            with tempfile.NamedTemporaryFile(
                mode="w+", delete=False, suffix=".json", encoding="utf-8"
            ) as tmp_file:
                temp_path = tmp_file.name

            cmd = [
                "semgrep",
                "scan",
                "--config",
                self.rules_file,
                "--output",
                temp_path,
                "--json",
                target_path,
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=300,
            )

            if not os.path.exists(temp_path) or os.path.getsize(temp_path) == 0:
                print(
                    f"Error: Temp file empty or missing. Return code: {result.returncode}"
                )
                os.unlink(temp_path)
                return False

            with open(temp_path, "r", encoding="utf-8") as f:
                output = f.read()

            os.unlink(temp_path)

            if not output.strip():
                print("Warning: Semgrep returned empty JSON")
                self.findings = []
                self.scan_metadata = {
                    "timestamp": datetime.now().isoformat(),
                    "target": target_path,
                    "rules_file": self.rules_file,
                    "total_findings": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                }
                return True

            data = json.loads(output)
            self.findings = data.get("results", [])

            critical = high = medium = low = 0
            for finding in self.findings:
                severity = finding.get("extra", {}).get("severity", "")
                if severity == "ERROR":
                    critical += 1
                elif severity == "HIGH":
                    high += 1
                elif severity == "MEDIUM":
                    medium += 1
                elif severity == "LOW":
                    low += 1

            self.scan_metadata = {
                "timestamp": datetime.now().isoformat(),
                "target": target_path,
                "rules_file": self.rules_file,
                "total_findings": len(self.findings),
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
            }

            print(f"\nDEBUG: Found {len(self.findings)} findings")
            if self.findings:
                f = self.findings[0]
                print(f"   Check ID: {f.get('check_id')}")
                print(f"   Path: {f.get('path')}")
                print(f"   Severity: {f.get('extra', {}).get('severity')}")

            return True

        except Exception as e:
            print(f"Error in run_semgrep: {e}")
            import traceback

            traceback.print_exc()
            return False

    def clone_github_repo(
        self, repo_url: str, token: Optional[str] = None
    ) -> Optional[str]:
        """Clone a GitHub repository to a temporary directory"""
        if not HAS_GITHUB:
            print("Error: PyGithub not installed. Run: pip install PyGithub")
            return None

        try:
            print(f"\nCloning repository: {repo_url}")

            temp_dir = tempfile.mkdtemp(prefix="healthcare_scan_")
            repo_name = repo_url.split("/")[-1].replace(".git", "")
            clone_path = os.path.join(temp_dir, repo_name)

            if token:
                g = Github(token)
                repo = g.get_repo(repo_url.replace("https://github.com/", ""))
                clone_url = f"https://{token}@github.com/{repo.full_name}.git"
            else:
                if not repo_url.endswith(".git"):
                    repo_url = repo_url + ".git"
                clone_url = repo_url

            result = subprocess.run(
                ["git", "clone", "--depth", "1", clone_url, clone_path],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode != 0:
                print(f"Error cloning repository: {result.stderr}")
                shutil.rmtree(temp_dir, ignore_errors=True)
                return None

            print(f"Repository cloned to: {clone_path}")
            return clone_path

        except Exception as e:
            print(f"Error cloning repository: {e}")
            import traceback

            traceback.print_exc()
            return None

    def scan_local_directory(self, target_path: str) -> bool:
        """Scan a local directory or file"""
        if not os.path.exists(target_path):
            print(f"Error: Path not found: {target_path}")
            return False

        print(f"\nScanning local path: {target_path}")
        return self.run_semgrep(target_path)

    def scan_github_repo(self, repo_url: str, token: Optional[str] = None) -> bool:
        """Scan a GitHub repository"""
        if not HAS_GITHUB:
            print("Error: PyGithub not installed. Run: pip install PyGithub")
            return False

        clone_path = self.clone_github_repo(repo_url, token)
        if not clone_path:
            return False

        try:
            success = self.run_semgrep(clone_path)

            self.repo_info = {
                "url": repo_url,
                "cloned_path": clone_path,
                "clone_time": datetime.now().isoformat(),
            }

            return success

        finally:
            print(f"\nCleaning up temporary files...")
            shutil.rmtree(clone_path, ignore_errors=True)

    def calculate_risk_score(self) -> tuple:
        """Calculate compliance risk score and level"""
        total_score = 0
        for finding in self.findings:
            severity = finding.get("extra", {}).get("severity", "")
            if severity == "ERROR":
                total_score += 10
            elif severity == "HIGH":
                total_score += 7
            elif severity == "MEDIUM":
                total_score += 4
            elif severity == "LOW":
                total_score += 1

        if total_score >= 20:
            level = "CRITICAL"
        elif total_score >= 10:
            level = "HIGH"
        elif total_score >= 5:
            level = "MEDIUM"
        else:
            level = "LOW"

        return total_score, level

    def generate_word_report(self, output_path: str) -> bool:
        """Generate Microsoft Word report with HIPAA compliance mapping and remediation"""
        if not HAS_DOCX:
            print("Error: python-docx not installed")
            return False

        doc = Document()

        # Title
        title = doc.add_heading("Healthcare Code Security Assessment Report", 0)
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER

        # Metadata
        doc.add_paragraph(f"Generated: {self.scan_metadata.get('timestamp', 'N/A')}")
        if self.repo_info:
            doc.add_paragraph(f"Repository: {self.repo_info.get('url', 'N/A')}")
        else:
            doc.add_paragraph(f"Target: {self.scan_metadata.get('target', 'N/A')}")
        doc.add_paragraph(f"Rules File: {self.scan_metadata.get('rules_file', 'N/A')}")
        doc.add_paragraph("-" * 50)

        # Executive Summary
        doc.add_heading("Executive Summary", level=1)
        summary = doc.add_paragraph()
        summary.add_run(
            f"Total Findings: {self.scan_metadata['total_findings']}"
        ).bold = True
        summary.add_run("\n")
        summary.add_run(f"Critical: {self.scan_metadata['critical']}").bold = True
        summary.add_run(f" | High: {self.scan_metadata['high']}").bold = True
        summary.add_run(f" | Medium: {self.scan_metadata['medium']}").bold = True
        summary.add_run(f" | Low: {self.scan_metadata['low']}").bold = True

        # Risk Assessment
        doc.add_heading("Risk Assessment", level=1)
        if self.scan_metadata["critical"] > 0:
            doc.add_paragraph(
                "CRITICAL: Immediate action required. Patient data may be at risk."
            )
        elif self.scan_metadata["high"] > 0:
            doc.add_paragraph(
                "HIGH: Significant vulnerabilities detected. Remediation recommended before deployment."
            )
        else:
            doc.add_paragraph("LOW RISK: No critical vulnerabilities detected.")

        # HIPAA Compliance Overview
        doc.add_heading("HIPAA Compliance Overview", level=1)

        hipaa_sections = {}
        for finding in self.findings:
            hipaa_ref = (
                finding.get("extra", {}).get("metadata", {}).get("hipaa_reference", "")
            )
            hipaa_sub = (
                finding.get("extra", {}).get("metadata", {}).get("hipaa_subsection", "")
            )
            if hipaa_ref:
                if hipaa_ref not in hipaa_sections:
                    hipaa_sections[hipaa_ref] = {"subsection": hipaa_sub, "count": 0}
                hipaa_sections[hipaa_ref]["count"] += 1

        if hipaa_sections:
            table_data = [["HIPAA Section", "Subsection", "Findings", "Status"]]
            for section, data in sorted(hipaa_sections.items()):
                status = "Non-Compliant" if data["count"] > 0 else "Compliant"
                table_data.append(
                    [section, data["subsection"], str(data["count"]), status]
                )

            table = doc.add_table(rows=1, cols=4)
            table.style = "Table Grid"
            hdr_cells = table.rows[0].cells
            hdr_cells[0].text = "HIPAA Section"
            hdr_cells[1].text = "Subsection"
            hdr_cells[2].text = "Findings"
            hdr_cells[3].text = "Status"

            for row_data in table_data[1:]:
                row = table.add_row().cells
                for i, cell_text in enumerate(row_data):
                    row[i].text = cell_text
        else:
            doc.add_paragraph("No HIPAA-specific rules triggered.")

        # Compliance Checklist
        doc.add_heading("HIPAA Compliance Checklist", level=1)
        checklist_items = [
            (
                "164.308(a)(1)",
                "Administrative Safeguards - Security Management Process",
            ),
            ("164.310(a)(1)", "Physical Safeguards - Facility Access Controls"),
            ("164.312(a)(1)", "Technical Safeguards - Access Control"),
            ("164.312(d)", "Technical Safeguards - Integrity Controls"),
            ("164.312(e)(1)", "Technical Safeguards - Transmission Security"),
        ]

        checklist_table = doc.add_table(rows=1, cols=3)
        checklist_table.style = "Table Grid"
        hdr = checklist_table.rows[0].cells
        hdr[0].text = "Section"
        hdr[1].text = "Requirement"
        hdr[2].text = "Status"

        for section, requirement in checklist_items:
            has_findings = any(section in hipaa_sections for section in [section])
            status = "Non-Compliant" if has_findings else "Compliant"
            row = checklist_table.add_row().cells
            row[0].text = section
            row[1].text = requirement
            row[2].text = status

        # Risk Score Calculation
        doc.add_heading("Compliance Risk Score", level=1)
        total_score, risk_level = self.calculate_risk_score()

        score_p = doc.add_paragraph()
        score_p.add_run(f"Total Risk Score: {total_score}").bold = True
        score_p.add_run(f" (Level: {risk_level})")

        # Remediation Timeline
        doc.add_heading("Remediation Timeline", level=1)
        timeline = {}
        for finding in self.findings:
            priority = (
                finding.get("extra", {})
                .get("metadata", {})
                .get("remediation_priority", "Medium")
            )
            days = (
                finding.get("extra", {})
                .get("metadata", {})
                .get("max_remediation_days", 30)
            )
            if priority not in timeline:
                timeline[priority] = {"days": days, "count": 0}
            timeline[priority]["count"] += 1

        for priority, data in sorted(timeline.items(), key=lambda x: x[1]["days"]):
            doc.add_paragraph(
                f"{priority}: {data['count']} findings - Remediate within {data['days']} days"
            )

        # Detailed Findings with HIPAA Mapping and Remediation
        doc.add_heading("Detailed Findings with HIPAA Mapping and Remediation", level=1)

        if not self.findings:
            doc.add_paragraph("No security vulnerabilities detected.")
        else:
            for i, finding in enumerate(self.findings, 1):
                start = finding.get("start", {})
                extra = finding.get("extra", {})
                metadata = extra.get("metadata", {})
                rule_id = finding.get("check_id", "")

                # Get remediation template
                remediation = (
                    get_remediation(rule_id)
                    if HAS_REMEDIATIONS
                    else {
                        "title": "General Remediation",
                        "description": "Review and fix this issue.",
                        "steps": ["Fix the issue manually."],
                        "before": "N/A",
                        "after": "N/A",
                        "resources": [],
                        "severity_impact": "Unknown",
                    }
                )

                # Finding Header
                doc.add_heading(f"Finding #{i}: {rule_id}", level=2)
                doc.add_paragraph(f"**File:** {finding.get('path', 'Unknown')}")
                doc.add_paragraph(f"**Line:** {start.get('line', 'N/A')}")
                doc.add_paragraph(f"**Severity:** {extra.get('severity', 'Unknown')}")
                doc.add_paragraph(f"**Message:** {extra.get('message', 'No message')}")

                # HIPAA Compliance
                doc.add_paragraph("**HIPAA Compliance:**")
                doc.add_paragraph(
                    f"- Section: {metadata.get('hipaa_reference', 'N/A')}"
                )
                doc.add_paragraph(
                    f"- Subsection: {metadata.get('hipaa_subsection', 'N/A')}"
                )
                doc.add_paragraph(
                    f"- Priority: {metadata.get('remediation_priority', 'Medium')}"
                )
                doc.add_paragraph(
                    f"- Max Days: {metadata.get('max_remediation_days', 30)}"
                )

                # Impact
                doc.add_paragraph(
                    f"**Impact:** {remediation.get('severity_impact', 'Unknown')}"
                )

                # Description
                doc.add_paragraph("**Description:**")
                doc.add_paragraph(
                    remediation.get("description", "No description available.")
                )

                # Remediation Steps
                doc.add_paragraph("**Remediation Steps:**")
                steps = remediation.get("steps", [])
                for j, step in enumerate(steps, 1):
                    doc.add_paragraph(f"{j}. {step}", style="List Number")

                # Before/After Code
                doc.add_paragraph("**Code Example:**")
                doc.add_paragraph("Before (Vulnerable):", style="Heading 3")

                # Add code block for 'before'
                before_para = doc.add_paragraph()
                before_para.add_run(remediation.get("before", "N/A"))
                before_para.style = "No Spacing"

                doc.add_paragraph("After (Fixed):", style="Heading 3")

                # Add code block for 'after'
                after_para = doc.add_paragraph()
                after_para.add_run(remediation.get("after", "N/A"))
                after_para.style = "No Spacing"

                # External Resources
                resources = remediation.get("resources", [])
                if resources:
                    doc.add_paragraph("**Additional Resources:**")
                    for title, url in resources:
                        doc.add_paragraph(f"- [{title}]({url})", style="List Bullet")

                doc.add_paragraph("-" * 50)

        doc.save(output_path)
        print(f"Word report saved to: {output_path}")
        return True

    def generate_pdf_report(self, output_path: str) -> bool:
        """Generate PDF report with HIPAA compliance mapping and remediation"""
        if not HAS_REPORTLAB:
            print("Error: reportlab not installed")
            return False

        doc = SimpleDocTemplate(output_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=24,
            textColor=colors.HexColor("#003366"),
            spaceAfter=30,
        )
        story.append(
            Paragraph("Healthcare Code Security Assessment Report", title_style)
        )
        story.append(Spacer(1, 20))

        # Metadata
        meta_style = styles["Normal"]
        story.append(
            Paragraph(
                f"<b>Generated:</b> {self.scan_metadata.get('timestamp', 'N/A')}",
                meta_style,
            )
        )
        if self.repo_info:
            story.append(
                Paragraph(
                    f"<b>Repository:</b> {self.repo_info.get('url', 'N/A')}", meta_style
                )
            )
        else:
            story.append(
                Paragraph(
                    f"<b>Target:</b> {self.scan_metadata.get('target', 'N/A')}",
                    meta_style,
                )
            )
        story.append(
            Paragraph(
                f"<b>Total Findings:</b> {self.scan_metadata['total_findings']}",
                meta_style,
            )
        )
        story.append(Spacer(1, 20))

        # Risk Summary
        story.append(Paragraph("<b>Risk Assessment</b>", styles["Heading2"]))
        if self.scan_metadata["critical"] > 0:
            story.append(
                Paragraph(
                    "CRITICAL: Immediate action required. Patient data may be at risk.",
                    styles["Normal"],
                )
            )
        elif self.scan_metadata["high"] > 0:
            story.append(
                Paragraph(
                    "HIGH: Significant vulnerabilities detected.", styles["Normal"]
                )
            )
        else:
            story.append(
                Paragraph(
                    "LOW RISK: No critical vulnerabilities detected.", styles["Normal"]
                )
            )
        story.append(Spacer(1, 20))

        # HIPAA Compliance Overview
        story.append(Paragraph("<b>HIPAA Compliance Overview</b>", styles["Heading2"]))

        hipaa_sections = {}
        for finding in self.findings:
            hipaa_ref = (
                finding.get("extra", {}).get("metadata", {}).get("hipaa_reference", "")
            )
            if hipaa_ref:
                if hipaa_ref not in hipaa_sections:
                    hipaa_sections[hipaa_ref] = 0
                hipaa_sections[hipaa_ref] += 1

        if hipaa_sections:
            for section, count in sorted(hipaa_sections.items()):
                story.append(
                    Paragraph(f"- {section}: {count} findings", styles["Normal"])
                )
        else:
            story.append(
                Paragraph("No HIPAA-specific rules triggered.", styles["Normal"])
            )
        story.append(Spacer(1, 20))

        # Risk Score
        total_score, risk_level = self.calculate_risk_score()
        story.append(
            Paragraph(
                f"<b>Compliance Risk Score:</b> {total_score} (Level: {risk_level})",
                styles["Heading3"],
            )
        )
        story.append(Spacer(1, 20))

        # Detailed Findings
        story.append(
            Paragraph("<b>Detailed Findings with Remediation</b>", styles["Heading2"])
        )

        if not self.findings:
            story.append(
                Paragraph("No security vulnerabilities detected.", styles["Normal"])
            )
        else:
            for finding in self.findings:
                start = finding.get("start", {})
                extra = finding.get("extra", {})
                rule_id = finding.get("check_id", "")
                remediation = (
                    get_remediation(rule_id)
                    if HAS_REMEDIATIONS
                    else {
                        "description": "No description.",
                        "steps": [],
                        "before": "N/A",
                        "after": "N/A",
                        "severity_impact": "Unknown",
                    }
                )

                story.append(Paragraph(f"<b>{rule_id}</b>", styles["Heading3"]))
                story.append(
                    Paragraph(
                        f"File: {finding.get('path', 'Unknown')} | Line: {start.get('line', 'N/A')}",
                        styles["Normal"],
                    )
                )
                story.append(
                    Paragraph(
                        f"Severity: {extra.get('severity', 'Unknown')}",
                        styles["Normal"],
                    )
                )
                story.append(
                    Paragraph(
                        f"Impact: {remediation.get('severity_impact', 'Unknown')}",
                        styles["Normal"],
                    )
                )

                story.append(Paragraph("<b>Description:</b>", styles["Heading4"]))
                story.append(
                    Paragraph(remediation.get("description", "N/A"), styles["Normal"])
                )

                story.append(Paragraph("<b>Remediation Steps:</b>", styles["Heading4"]))
                for step in remediation.get("steps", []):
                    story.append(Paragraph(f"• {step}", styles["Normal"]))

                story.append(Paragraph("<b>Code Example:</b>", styles["Heading4"]))
                before_text = remediation.get("before", "N/A")
                after_text = remediation.get("after", "N/A")
                # Truncate long code for PDF readability
                story.append(
                    Paragraph(
                        f"Before: {before_text[:100]}{'...' if len(before_text) > 100 else ''}",
                        styles["Normal"],
                    )
                )
                story.append(
                    Paragraph(
                        f"After: {after_text[:100]}{'...' if len(after_text) > 100 else ''}",
                        styles["Normal"],
                    )
                )

                story.append(Spacer(1, 10))

        doc.build(story)
        print(f"PDF report saved to: {output_path}")
        return True


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="Healthcare Code Security Scanner")
    parser.add_argument("target", help="Path to directory/file OR GitHub repo URL")
    parser.add_argument(
        "--rules", default="healthcare_rules.yaml", help="Semgrep rules file"
    )
    parser.add_argument(
        "--output",
        default="security_report",
        help="Output filename (without extension)",
    )
    parser.add_argument(
        "--format",
        choices=["word", "pdf", "both"],
        default="both",
        help="Report format",
    )
    parser.add_argument(
        "--github-token", help="GitHub personal access token for private repos"
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Force local scan (don't treat as GitHub URL)",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("Healthcare Code Security Scanner")
    print("=" * 60)

    scanner = SecurityScanner(rules_file=args.rules)

    is_github = False
    if not args.local and (
        args.target.startswith("http") or args.target.startswith("git@")
    ):
        is_github = True

    if is_github:
        print(f"\nTarget: GitHub Repository")
        print(f"Rules: {args.rules}")

        if not scanner.scan_github_repo(args.target, args.github_token):
            print("GitHub scan failed!")
            sys.exit(1)
    else:
        print(f"\nTarget: Local Path")
        print(f"Rules: {args.rules}")

        if not scanner.scan_local_directory(args.target):
            print("Local scan failed!")
            sys.exit(1)

    print(f"\nScan complete. Found {scanner.scan_metadata['total_findings']} issues:")
    print(f"   Critical: {scanner.scan_metadata['critical']}")
    print(f"   High: {scanner.scan_metadata['high']}")
    print(f"   Medium: {scanner.scan_metadata['medium']}")
    print(f"   Low: {scanner.scan_metadata['low']}")

    if args.format in ["word", "both"]:
        word_path = f"{args.output}.docx"
        if scanner.generate_word_report(word_path):
            print(f"\nWord report: {word_path}")

    if args.format in ["pdf", "both"]:
        pdf_path = f"{args.output}.pdf"
        if scanner.generate_pdf_report(pdf_path):
            print(f"PDF report: {pdf_path}")

    print("\n" + "=" * 60)
    print("Scan complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
