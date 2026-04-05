#!/usr/bin/env python3
"""
Remediation Templates for Healthcare Security Scanner
Maps each rule to specific code fixes and guidance
"""

REMEDIATION_TEMPLATES = {
    "hardcoded-credentials-all-languages": {
        "title": "Remove Hardcoded Credentials",
        "description": "Hardcoded credentials pose a critical risk to patient data security. Move all secrets to environment variables or a secrets manager.",
        "steps": [
            "Identify all hardcoded credentials in your codebase",
            "Create environment variables for each credential",
            "Update code to read from environment variables",
            "Add .env to .gitignore to prevent accidental commits",
            "Consider using AWS Secrets Manager, Azure Key Vault, or HashiCorp Vault for production",
        ],
        "before": '''# BAD: Hardcoded credentials
api_key = "sk-proj-1234567890abcdef"
password = "MySecretPassword123"
database_url = "postgresql://admin:password123@localhost/db"''',
        "after": """# GOOD: Environment variables
import os

api_key = os.environ.get("API_KEY")
password = os.environ.get("DATABASE_PASSWORD")
database_url = os.environ.get("DATABASE_URL")

# Or using a secrets manager
from dotenv import load_dotenv
load_dotenv()  # Load from .env file in development""",
        "resources": [
            (
                "OWASP - Managing Sensitive Data",
                "https://cheatsheetseries.owasp.org/cheatsheets/Credential_Management_Cheat_Sheet.html",
            ),
            ("12-Factor App - Config", "https://12factor.net/config"),
            (
                "Python os.environ Documentation",
                "https://docs.python.org/3/library/os.html#os.environ",
            ),
        ],
        "severity_impact": "Critical - Direct exposure of authentication credentials",
    },
    "unencrypted-http-request": {
        "title": "Enforce HTTPS/TLS for All Requests",
        "description": "Unencrypted HTTP transmissions can expose Protected Health Information (PHI) to man-in-the-middle attacks.",
        "steps": [
            "Replace all 'http://' URLs with 'https://'",
            "Enable TLS 1.2 or higher on all servers",
            "Implement certificate validation",
            "Consider using HSTS headers for web applications",
            "Use a library like requests with verify=True",
        ],
        "before": """# BAD: Unencrypted HTTP
import requests

url = "http://api.hospital-system.com/patient/123"
response = requests.get(url)""",
        "after": """# GOOD: Encrypted HTTPS with verification
import requests

url = "https://api.hospital-system.com/patient/123"
response = requests.get(url, verify=True)  # Verify SSL certificate

# For production, consider pinning certificates
# response = requests.get(url, verify='/path/to/cert.pem')""",
        "resources": [
            (
                "OWASP - Transport Layer Protection",
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
            ),
            (
                "NIST TLS Guidelines",
                "https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final",
            ),
            (
                "Requests Library SSL",
                "https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification",
            ),
        ],
        "severity_impact": "Critical - PHI exposed in transit",
    },
    "insecure-deserialization-pickle": {
        "title": "Replace Unsafe Deserialization",
        "description": "Pickle deserialization can lead to Remote Code Execution (RCE) if an attacker controls the serialized data.",
        "steps": [
            "Identify all pickle.loads() and pickle.load() calls",
            "Replace with JSON or other safe serialization formats",
            "If pickle is absolutely necessary, validate data integrity",
            "Consider using msgpack or protobuf for binary data",
            "Never deserialize data from untrusted sources",
        ],
        "before": """# BAD: Unsafe pickle deserialization
import pickle

def load_patient_record(data):
    return pickle.loads(data)  # DANGEROUS!""",
        "after": """# GOOD: Safe JSON deserialization
import json

def load_patient_record(data):
    return json.loads(data)  # Safe

# For binary data, use msgpack
import msgpack
def load_binary_record(data):
    return msgpack.unpackb(data)""",
        "resources": [
            (
                "OWASP - Deserialization Cheat Sheet",
                "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
            ),
            ("Python json Module", "https://docs.python.org/3/library/json.html"),
            ("msgpack Documentation", "https://msgpack.org/"),
        ],
        "severity_impact": "Critical - Remote Code Execution risk",
    },
    "potential-sql-injection-string-formatting": {
        "title": "Use Parameterized Queries",
        "description": "String formatting in SQL queries allows attackers to inject malicious SQL commands, potentially exposing or modifying patient records.",
        "steps": [
            "Identify all SQL queries using string formatting",
            "Replace with parameterized queries using placeholders",
            "Use ORM frameworks (SQLAlchemy, Django ORM) when possible",
            "Implement input validation as defense-in-depth",
            "Apply principle of least privilege to database accounts",
        ],
        "before": """# BAD: SQL Injection vulnerability
query = "SELECT * FROM patients WHERE name = '%s'" % name
cursor.execute(query)

# Also bad: f-strings
query = f"SELECT * FROM patients WHERE id = {patient_id}"
cursor.execute(query)""",
        "after": """# GOOD: Parameterized query
query = "SELECT * FROM patients WHERE name = %s"
cursor.execute(query, (name,))

# Or with named parameters
query = "SELECT * FROM patients WHERE id = :id"
cursor.execute(query, {"id": patient_id})

# Best: Use an ORM
from sqlalchemy import select
stmt = select(Patient).where(Patient.name == name)
results = session.execute(stmt)""",
        "resources": [
            (
                "OWASP - SQL Injection Prevention",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            ),
            (
                "PEP 249 - Python DB-API",
                "https://peps.python.org/pep-0249/#parameter-style",
            ),
            ("SQLAlchemy Documentation", "https://docs.sqlalchemy.org/"),
        ],
        "severity_impact": "Critical - Data theft or modification",
    },
    "weak-random-generation": {
        "title": "Use Cryptographically Secure Random Generation",
        "description": "The 'random' module is not suitable for security-sensitive operations like token generation. Use the 'secrets' module instead.",
        "steps": [
            "Identify all uses of random.random(), random.randint(), etc.",
            "Replace with secrets module equivalents",
            "For tokens, use secrets.token_hex() or secrets.token_urlsafe()",
            "For passwords, use secrets.choice() with a strong alphabet",
            "Review all session ID and API key generation",
        ],
        "before": """# BAD: Insecure random for security tokens
import random

def generate_session_token():
    return str(random.random())

def generate_password():
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return ''.join(random.choice(chars) for _ in range(8))""",
        "after": """# GOOD: Cryptographically secure random
import secrets
import string

def generate_session_token():
    return secrets.token_urlsafe(32)  # 256-bit token

def generate_password(length=16):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# For API keys
api_key = secrets.token_hex(32)""",
        "resources": [
            ("Python secrets Module", "https://docs.python.org/3/library/secrets.html"),
            (
                "OWASP - Cryptographic Storage",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
            ),
            (
                "NIST Randomness Guidelines",
                "https://csrc.nist.gov/projects/random-bit-generation",
            ),
        ],
        "severity_impact": "Medium - Session hijacking risk",
    },
}


def get_remediation(rule_id: str) -> dict:
    """Get remediation template for a given rule ID"""
    return REMEDIATION_TEMPLATES.get(
        rule_id,
        {
            "title": "General Security Remediation",
            "description": "Review and address this security finding according to industry best practices.",
            "steps": [
                "Analyze the vulnerability in context",
                "Consult security documentation",
                "Implement appropriate fixes",
                "Test the remediation",
                "Document the changes",
            ],
            "before": "N/A",
            "after": "N/A",
            "resources": [],
            "severity_impact": "Unknown",
        },
    )


def generate_remediation_section(findings: list) -> list:
    """Generate remediation sections for all findings"""
    sections = []
    for finding in findings:
        rule_id = finding.get("check_id", "")
        remediation = get_remediation(rule_id)

        section = {
            "rule_id": rule_id,
            "file": finding.get("path", "Unknown"),
            "line": finding.get("start", {}).get("line", "N/A"),
            "severity": finding.get("extra", {}).get("severity", "Unknown"),
            **remediation,
        }
        sections.append(section)

    return sections
