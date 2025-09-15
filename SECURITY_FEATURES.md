# Security Analysis Features

This document describes the new security analysis features added to the Webscrape tool (v2.2.0).

## Overview

The security analysis feature helps identify potential vulnerabilities in web applications by analyzing:

- **IDOR (Insecure Direct Object Reference) vulnerabilities** - Parameters that might allow unauthorized access to data
- **Injection vulnerabilities** - Input fields that could be vulnerable to SQL injection, XSS, Command injection, etc.
- **Form security issues** - Missing CSRF protection, file uploads, hidden inputs
- **AJAX endpoints** - JavaScript endpoints that might be testable

## Usage

### Single Page Analysis
```bash
python webscrape.py https://example.com --security
```

### Spider Crawling with Security Analysis
```bash
python webscrape.py https://example.com --spider --security --depth 3
```

### Generate Security Report
```bash
python webscrape.py https://example.com --security -o security_report.html
```

## Security Findings Categories

### High Risk Findings
- **File Upload Forms** - Forms that allow file uploads without restrictions
- **Potential IDOR Vulnerabilities** - URLs with ID parameters that might be manipulable
- **Command Injection** - Input fields that might execute system commands

### Medium Risk Findings
- **CSRF Vulnerabilities** - Forms without CSRF protection
- **SQL Injection** - Input fields that might be vulnerable to database attacks
- **XSS Vulnerabilities** - Input fields that might execute client-side scripts
- **Hidden Input Fields** - Forms with hidden inputs that might be manipulated
- **AJAX Endpoints** - JavaScript endpoints that might bypass authentication

### Low Risk Findings
- **Path Traversal** - Input fields that might access unauthorized files
- **LDAP Injection** - Directory service input fields

## IDOR Detection

The tool automatically identifies parameters that commonly indicate IDOR vulnerabilities:

- `id`, `user_id`, `userid`, `uid`
- `account_id`, `profile_id`, `doc_id`
- `file_id`, `document_id`, `order_id`
- `ticket_id`, `message_id`, `post_id`
- `product_id`, `customer_id`, `client_id`
- `reference`, `ref`, `key`, `token`
- `session_id`, `auth_id`, `admin_id`

## Injection Vulnerability Detection

The tool analyzes input field names and placeholders to identify potential injection points:

### SQL Injection Indicators
- `search`, `query`, `filter`, `where`, `select`
- `username`, `login`, `email`

### XSS Indicators
- `comment`, `message`, `content`, `description`
- `text`, `name`, `title`

### Command Injection Indicators
- `command`, `cmd`, `exec`, `system`, `shell`, `run`

### Path Traversal Indicators
- `file`, `path`, `dir`, `folder`, `upload`, `download`, `include`

## Report Features

### Console Output
- Summary of findings with counts and risk scores
- Detailed high-risk and medium-risk findings
- Testing suggestions for each vulnerability

### HTML Report
- Interactive security dashboard
- Color-coded risk levels
- Clickable URLs for testing
- Comprehensive security recommendations
- Professional styling for easy reading

## Risk Scoring

The tool calculates a risk score based on findings:
- High risk findings: 7-10 points each
- Medium risk findings: 3-5 points each
- Low risk findings: 2 points each

## Security Recommendations

The tool provides specific recommendations based on findings:

- Implement proper authorization checks for IDOR prevention
- Add CSRF protection to all state-changing forms
- Validate and sanitize all user inputs server-side
- Use parameterized queries for SQL injection prevention
- Restrict file upload types and validate file contents
- Implement Content Security Policy (CSP) headers
- Use HTTPS for all sensitive data transmission

## Example Usage Scenarios

### Bug Bounty Hunting
```bash
# Quick security scan of a target
python webscrape.py https://target.com --security -o target_security.html

# Deep spider scan for comprehensive analysis
python webscrape.py https://target.com --spider --security --depth 4 --delay 2.0 -o deep_scan.html
```

### Penetration Testing
```bash
# Analyze specific application sections
python webscrape.py https://app.com/admin --security
python webscrape.py https://app.com/user --security

# Generate professional security report
python webscrape.py https://app.com --spider --security --exclude "logout" "static" -o pentest_report.html
```

### Security Assessment
```bash
# Comprehensive security analysis with custom exclusions
python webscrape.py https://webapp.com --spider --security --depth 3 --exclude "api/docs" "help" --delay 1.5
```

## Important Notes

- **Ethical Usage**: Only use these features on websites you own or have explicit permission to test
- **Rate Limiting**: The tool respects rate limits and includes delays between requests
- **False Positives**: Manual verification is required for all findings
- **Legal Compliance**: Ensure compliance with local laws and website terms of service

## Integration with Security Testing

The findings from this tool can be used as input for:
- Manual security testing
- Automated vulnerability scanners
- Burp Suite or OWASP ZAP testing
- Custom security test scripts

## Contributing

If you find additional vulnerability patterns or have suggestions for improvements, please contribute to the project at: https://github.com/7a6179657473/Webscrape
