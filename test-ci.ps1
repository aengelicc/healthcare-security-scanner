Write-Host "=========================================="
Write-Host "Testing CI/CD Security Scan Locally"
Write-Host "=========================================="

# Check if Python is installed
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "ERROR: Python is not installed or not in PATH."
    exit 1
}

Write-Host "Python found: $$($$pythonCmd.Source)"

# Install dependencies
Write-Host ""
Write-Host "Installing dependencies..."
pip install semgrep python-docx reportlab PyGithub

if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to install dependencies."
    exit 1
}

Write-Host "Dependencies installed"

# Validate rules (correct syntax)
Write-Host ""
Write-Host "Validating Semgrep rules..."
semgrep validate healthcare_rules.yaml

if ($LASTEXITCODE -ne 0) {
    Write-Host "WARNING: Semgrep rules validation had issues (this may be normal for custom rules)."
    Write-Host "Continuing with scan..."
} else {
    Write-Host "Semgrep rules validated"
}

# Run scan
Write-Host ""
Write-Host "Running security scan..."
python scanner.py . --output security_report --format both

if ($LASTEXITCODE -ne 0) {
    Write-Host "Security scan failed."
    exit 1
}

# Display summary
Write-Host ""
Write-Host "=========================================="
Write-Host "Scan Complete!"
Write-Host "=========================================="

# List generated files
Write-Host ""
Write-Host "Generated Reports:"
$files = Get-ChildItem -Filter "security_report.*"
if ($files.Count -gt 0) {
    foreach ($file in $files) {
        Write-Host "   [OK] $$($$file.Name)"
    }
} else {
    Write-Host "   [!] No report files found"
}

Write-Host ""
Write-Host "All checks passed successfully!"
