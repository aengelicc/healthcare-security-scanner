#!/usr/bin/env python3
"""
Healthcare Code Security Scanner
Generates PDF/Word reports from Semgrep findings
Supports local directories AND GitHub repositories
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

try:
    from docx import Document
    from docx.enum.style import WD_STYLE_TYPE
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
            # Create a temporary file to store JSON output
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

            # Read the file content
            if not os.path.exists(temp_path) or os.path.getsize(temp_path) == 0:
                print(
                    f"Error: Temp file empty or missing. Return code: {result.returncode}"
                )
                if result.stderr:
                    print(f"Semgrep stderr: {result.stderr[:500]}")
                os.unlink(temp_path)
                return False

            with open(temp_path, "r", encoding="utf-8") as f:
                output = f.read()

            # Clean up temp file
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

            # Extract findings
            self.findings = data.get("results", [])

            # Count severities
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

            # Debug
            print(f"\n🔍 DEBUG: Found {len(self.findings)} findings")
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
            print(f"\n📥 Cloning repository: {repo_url}")

            # Create temp directory for clone
            temp_dir = tempfile.mkdtemp(prefix="healthcare_scan_")
            repo_name = repo_url.split("/")[-1].replace(".git", "")
            clone_path = os.path.join(temp_dir, repo_name)

            # Authenticate if token provided
            if token:
                g = Github(token)
                repo = g.get_repo(repo_url.replace("https://github.com/", ""))
                # Get clone URL with token embedded
                clone_url = f"https://{token}@github.com/{repo.full_name}.git"
            else:
                # Public repo - no auth needed
                if not repo_url.endswith(".git"):
                    repo_url = repo_url + ".git"
                clone_url = repo_url

            # Clone using git command (more reliable than PyGithub for large repos)
            import subprocess

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

            print(f"✅ Repository cloned to: {clone_path}")
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

        print(f"\n🔍 Scanning local path: {target_path}")
        return self.run_semgrep(target_path)

    def scan_github_repo(self, repo_url: str, token: Optional[str] = None) -> bool:
        """Scan a GitHub repository"""
        if not HAS_GITHUB:
            print("Error: PyGithub not installed. Run: pip install PyGithub")
            return False

        # Clone the repository
        clone_path = self.clone_github_repo(repo_url, token)
        if not clone_path:
            return False

        try:
            # Scan the cloned repository
            success = self.run_semgrep(clone_path)

            # Store repo info for reporting
            self.repo_info = {
                "url": repo_url,
                "cloned_path": clone_path,
                "clone_time": datetime.now().isoformat(),
            }

            return success

        finally:
            # Clean up: remove cloned repository
            print(f"\n🧹 Cleaning up temporary files...")
            shutil.rmtree(clone_path, ignore_errors=True)

    def generate_word_report(self, output_path: str) -> bool:
        """Generate Microsoft Word report"""
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
                "⚠️ CRITICAL: Immediate action required. Patient data may be at risk."
            )
        elif self.scan_metadata["high"] > 0:
            doc.add_paragraph(
                "⚡ HIGH: Significant vulnerabilities detected. Remediation recommended before deployment."
            )
        else:
            doc.add_paragraph("✓ LOW RISK: No critical vulnerabilities detected.")

        # HIPAA Compliance Summary
        doc.add_heading("HIPAA Compliance Overview", level=1)
        compliance_sections = set()
        for finding in self.findings:
            hipaa_ref = (
                finding.get("extra", {}).get("metadata", {}).get("hipaa_reference", "")
            )
            if hipaa_ref:
                compliance_sections.add(hipaa_ref)

        if compliance_sections:
            for section in sorted(compliance_sections):
                doc.add_paragraph(f"• Affected: {section}")
        else:
            doc.add_paragraph("No HIPAA-specific rules triggered.")

        # Findings Table
        doc.add_heading("Detailed Findings", level=1)

        if not self.findings:
            doc.add_paragraph("No security vulnerabilities detected.")
        else:
            # Group findings by file
            findings_by_file = {}
            for finding in self.findings:
                path = finding.get("path", "Unknown")
                if path not in findings_by_file:
                    findings_by_file[path] = []
                findings_by_file[path].append(finding)

            # Create table
            table_data = [["File", "Line", "Rule ID", "Severity", "Message"]]
            for path, file_findings in findings_by_file.items():
                for finding in file_findings:
                    start = finding.get("start", {})
                    extra = finding.get("extra", {})
                    table_data.append(
                        [
                            path,
                            str(start.get("line", "N/A")),
                            finding.get("check_id", "Unknown"),
                            extra.get("severity", "Unknown"),
                            extra.get("message", "No message")[:50] + "...",
                        ]
                    )

            table = doc.add_table(rows=1, cols=5)
            table.style = "Table Grid"
            hdr_cells = table.rows[0].cells
            hdr_cells[0].text = "File"
            hdr_cells[1].text = "Line"
            hdr_cells[2].text = "Rule ID"
            hdr_cells[3].text = "Severity"
            hdr_cells[4].text = "Message"

            # Populate table
            for row_data in table_data[1:]:
                row = table.add_row().cells
                for i, cell_text in enumerate(row_data):
                    row[i].text = cell_text

        # Remediation Recommendations
        doc.add_heading("Remediation Recommendations", level=1)

        recommendations = {
            "ERROR": "CRITICAL: Address immediately. These vulnerabilities pose direct risk to patient data.",
            "HIGH": "HIGH PRIORITY: Remediate before production deployment.",
            "MEDIUM": "MEDIUM PRIORITY: Schedule for next sprint.",
            "LOW": "LOW PRIORITY: Address during routine maintenance.",
        }

        for severity, rec in recommendations.items():
            count = self.scan_metadata.get(severity.lower(), 0)
            if count > 0:
                p = doc.add_paragraph()
                p.add_run(f"{severity} ({count} findings): ").bold = True
                p.add_run(rec)

        # Save
        doc.save(output_path)
        print(f"Word report saved to: {output_path}")
        return True

    def generate_pdf_report(self, output_path: str) -> bool:
        """Generate PDF report using ReportLab"""
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
                    "⚠️ <b>CRITICAL:</b> Immediate action required. Patient data may be at risk.",
                    styles["Normal"],
                )
            )
        elif self.scan_metadata["high"] > 0:
            story.append(
                Paragraph(
                    "⚡ <b>HIGH:</b> Significant vulnerabilities detected.",
                    styles["Normal"],
                )
            )
        else:
            story.append(
                Paragraph(
                    "✓ <b>LOW RISK:</b> No critical vulnerabilities detected.",
                    styles["Normal"],
                )
            )
        story.append(Spacer(1, 20))

        # HIPAA Compliance
        story.append(Paragraph("<b>HIPAA Compliance Overview</b>", styles["Heading2"]))
        compliance_sections = set()
        for finding in self.findings:
            hipaa_ref = (
                finding.get("extra", {}).get("metadata", {}).get("hipaa_reference", "")
            )
            if hipaa_ref:
                compliance_sections.add(hipaa_ref)

        if compliance_sections:
            for section in sorted(compliance_sections):
                story.append(Paragraph(f"• Affected: {section}", styles["Normal"]))
        else:
            story.append(
                Paragraph("No HIPAA-specific rules triggered.", styles["Normal"])
            )
        story.append(Spacer(1, 20))

        # Findings
        story.append(Paragraph("<b>Detailed Findings</b>", styles["Heading2"]))

        if not self.findings:
            story.append(
                Paragraph("No security vulnerabilities detected.", styles["Normal"])
            )
        else:
            for finding in self.findings:
                start = finding.get("start", {})
                extra = finding.get("extra", {})
                severity = extra.get("severity", "Unknown")

                story.append(
                    Paragraph(
                        f"<b>{finding.get('check_id', 'Unknown')}</b>",
                        styles["Heading3"],
                    )
                )
                story.append(
                    Paragraph(
                        f"File: {finding.get('path', 'Unknown')} | Line: {start.get('line', 'N/A')}",
                        styles["Normal"],
                    )
                )
                story.append(Paragraph(f"Severity: {severity}", styles["Normal"]))
                story.append(
                    Paragraph(
                        f"Message: {extra.get('message', 'No message')}",
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

    # Initialize scanner
    scanner = SecurityScanner(rules_file=args.rules)

    # Determine if GitHub or local
    is_github = False
    if not args.local and (
        args.target.startswith("http") or args.target.startswith("git@")
    ):
        is_github = True

    if is_github:
        print(f"\n🔗 Target: GitHub Repository")
        print(f"📋 Rules: {args.rules}")

        if not scanner.scan_github_repo(args.target, args.github_token):
            print("❌ GitHub scan failed!")
            sys.exit(1)
    else:
        print(f"\n🔍 Target: Local Path")
        print(f"📋 Rules: {args.rules}")

        if not scanner.scan_local_directory(args.target):
            print("❌ Local scan failed!")
            sys.exit(1)

    print(
        f"\n✅ Scan complete. Found {scanner.scan_metadata['total_findings']} issues:"
    )
    print(f"   Critical: {scanner.scan_metadata['critical']}")
    print(f"   High: {scanner.scan_metadata['high']}")
    print(f"   Medium: {scanner.scan_metadata['medium']}")
    print(f"   Low: {scanner.scan_metadata['low']}")

    # Generate reports
    if args.format in ["word", "both"]:
        word_path = f"{args.output}.docx"
        if scanner.generate_word_report(word_path):
            print(f"\n📄 Word report: {word_path}")

    if args.format in ["pdf", "both"]:
        pdf_path = f"{args.output}.pdf"
        if scanner.generate_pdf_report(pdf_path):
            print(f"📑 PDF report: {pdf_path}")

    print("\n" + "=" * 60)
    print("Scan complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
