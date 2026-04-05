#!/bin/bash

echo "=========================================="
echo "Testing CI/CD Security Scan Locally"
echo "=========================================="

# Install dependencies
echo "📦 Installing dependencies..."
pip install semgrep python-docx reportlab PyGithub

# Validate rules
echo "🔍 Validating Semgrep rules..."
semgrep validate --config healthcare_rules.yaml

# Run scan
echo "🔬 Running security scan..."
python scanner.py . --output security_report --format both

# Display summary
echo ""
echo "=========================================="
echo "Scan Complete!"
echo "=========================================="
ls -la security_report.*

echo ""
echo "✅ Reports generated successfully"
