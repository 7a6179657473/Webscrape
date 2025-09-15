# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

This is a comprehensive Python web scraping utility with advanced security analysis capabilities that extracts links, email addresses, and identifies potential vulnerabilities in web applications. The project consists of a single Python script that uses requests and BeautifulSoup for web scraping functionality with enhanced link detection, email extraction, and security vulnerability assessment capabilities including IDOR detection and injection analysis.

## Architecture

The codebase follows a modular single-file architecture:

- **`webscrape.py`**: Main script containing the entire web scraping functionality
  - Takes user input for target URL with proper validation
  - Fetches webpage content using the `requests` library with browser-like headers
  - Parses HTML using `BeautifulSoup` with comprehensive link extraction
  - Extracts emails using regex patterns and HTML parsing
  - Provides detailed output with counts and organized results

### Key Functions:
- **`extract_links(soup, base_url)`**: Extracts all types of links including:
  - Anchor tags (`<a href>`)
  - CSS and resource links (`<link href>`)
  - Images (`<img src>`)
  - Scripts (`<script src>`)
  - Iframes (`<iframe src>`)
  - Converts relative URLs to absolute URLs

- **`extract_emails(soup, page_text)`**: Extracts email addresses from:
  - Page text content using regex
  - Mailto links
  - Data attributes

- **`generate_html_tree(url, links, emails, output_file)`**: Creates an interactive HTML report
  - Organizes links by domain in a tree structure
  - Includes professional styling and responsive design
  - Creates clickable links and mailto: links for emails
  - Shows summary statistics and timestamps

- **`parse_arguments()`**: Handles command-line argument parsing for URL and output options

- **`validate_url(url)`**: Validates URLs for security before making requests
  - Ensures only HTTP/HTTPS schemes are allowed
  - Validates URL format and length
  - Prevents malformed or dangerous URLs

- **`sanitize_filename(filename)`**: Sanitizes output filenames to prevent path traversal
  - Removes dangerous characters and path separators
  - Prevents directory traversal attacks
  - Enforces reasonable filename length limits

- **`main()`**: Orchestrates the scraping process with proper error handling and HTML generation

### Security Analysis Functions (v2.2.0+):
- **`extract_input_parameters(soup, base_url)`**: Identifies URLs with query parameters and form inputs for security testing
  - Extracts parameterized URLs and analyzes query parameters
  - Discovers HTML forms and input fields with detailed attributes
  - Identifies hidden inputs and file upload capabilities
  - Extracts AJAX endpoints from JavaScript code

- **`is_potential_idor_parameter(param_name, param_value)`**: Detects parameters vulnerable to IDOR attacks
  - Analyzes 25+ common IDOR parameter patterns (id, user_id, account_id, etc.)
  - Validates parameter values for ID-like patterns (numeric, UUID, hash)
  - Returns boolean indicating IDOR vulnerability potential

- **`identify_injection_vulnerability_type(field_name, placeholder)`**: Categorizes injection vulnerability types
  - SQL Injection detection (search, query, username, email fields)
  - XSS vulnerability identification (comment, message, content fields)
  - Command injection detection (command, exec, system fields)
  - Path traversal identification (file, path, upload fields)
  - LDAP injection detection (directory service fields)

- **`extract_ajax_endpoints(script_content, base_url)`**: Discovers AJAX endpoints from JavaScript
  - Supports jQuery, Fetch API, XMLHttpRequest, and Axios patterns
  - Extracts potential API endpoints for security testing
  - Converts relative URLs to absolute URLs

- **`analyze_security_findings(input_data, url)`**: Performs comprehensive vulnerability assessment
  - Calculates risk scores based on findings
  - Categorizes vulnerabilities into High, Medium, and Low risk levels
  - Provides specific testing suggestions for each vulnerability
  - Generates security recommendations based on discovered issues

## Dependencies

The project requires two main Python packages:
- **requests** (v2.25.0+): For HTTP requests and webpage fetching
- **beautifulsoup4** (v4.10.0+): For HTML parsing and link/email extraction

Built-in Python modules used:
- **re**: For regex pattern matching (email extraction)
- **urllib.parse**: For URL parsing and joining
- **sys**: For system operations and exit handling
- **argparse**: For command-line argument parsing
- **datetime**: For timestamp generation in HTML reports
- **os**: For file path operations
- **html**: For HTML escaping and security
- **time**: For delays between requests in spider mode
- **collections**: For deque data structure in spider crawling
- **threading**: For potential future concurrent operations

Python version: 3.11.9+ (tested with 3.11.9)

**Current Version**: 2.2.0 - Security Analysis Edition (September 2025)
- Added comprehensive security vulnerability detection
- IDOR and injection analysis capabilities
- Enhanced HTML reports with security dashboard
- Risk scoring and testing recommendations

## Common Development Commands

### Running the Web Scraper

**Interactive mode** (prompts for URL):
```bash
python webscrape.py
```

**Command line mode** with URL:
```bash
python webscrape.py https://example.com
```

**Save results to HTML file** (auto-generated filename):
```bash
python webscrape.py https://example.com -o
```

**Save results to specific HTML file**:
```bash
python webscrape.py https://example.com -o results.html
```

**View help and usage examples**:
```bash
python webscrape.py --help
```

### Security Analysis Commands (v2.2.0+)

**Single page security analysis**:
```bash
python webscrape.py https://example.com --security
```

**Spider crawling with security analysis**:
```bash
python webscrape.py https://example.com --spider --security --depth 3
```

**Generate security report**:
```bash
python webscrape.py https://example.com --security -o security_report.html
```

**Comprehensive security assessment**:
```bash
python webscrape.py https://webapp.com --spider --security --depth 4 --exclude "logout" "static" --delay 2.0 -o full_assessment.html
```

### Installing Dependencies
Install dependencies from requirements.txt:
```bash
pip install -r requirements.txt
```

Or install manually:
```bash
pip install requests beautifulsoup4
```

### Checking Dependencies
Verify installed packages:
```bash
python -c "import requests, bs4; print(f'requests: {requests.__version__}, bs4: {bs4.__version__}')"
```

## HTML Output Features

When using the `-o` flag, the script generates a professional HTML report with:

### Tree Structure
- Links organized by domain for easy navigation
- Collapsible domain groups with link counts
- Clean, hierarchical presentation

### Interactive Elements
- Clickable links that open in new tabs
- Mailto links for email addresses
- Hover effects and smooth transitions

### Report Contents
- Source URL and scraping timestamp
- Summary statistics (links, emails, domains)
- Responsive design for mobile and desktop
- Professional styling with modern CSS

### Auto-generated Filenames
When using `-o` without a filename, creates files like:
```
webscrape_example.com_20250915_002023.html
spider_example.com_20250915_002023.html
security_example.com_20250915_002023.html (with --security flag)
```

### Security Analysis Reports (v2.2.0+)
When using the `--security` flag, HTML reports include:

**Security Dashboard**:
- Overall risk score calculation
- High, Medium, and Low risk finding counts
- Potential IDOR parameter counts
- Color-coded risk indicators

**Vulnerability Findings**:
- High-risk findings (file uploads, IDOR vulnerabilities, command injection)
- Medium-risk findings (CSRF issues, SQL injection, XSS, hidden inputs, AJAX endpoints)
- Low-risk findings (path traversal, LDAP injection)
- Detailed testing suggestions for each finding

**Security Recommendations**:
- Specific remediation advice based on discovered vulnerabilities
- General security best practices
- Implementation guidelines for security controls

## Security Features

The script includes several security measures to prevent exploitation:

### Input Validation
- **URL Validation**: Only HTTP/HTTPS URLs are accepted
- **URL Length Limits**: Prevents excessively long URLs
- **Scheme Validation**: Blocks dangerous URL schemes

### Output Security
- **HTML Escaping**: All user-controlled content is escaped to prevent XSS
- **Path Traversal Prevention**: Filenames are sanitized to prevent directory traversal
- **Character Filtering**: Dangerous filename characters are removed

### Network Security
- **Timeout Protection**: 10-second timeout prevents hanging requests
- **Error Handling**: Graceful handling of network failures
- **User-Agent Headers**: Professional browser identification

### Security Analysis Testing (v2.2.0+)
Test security analysis functionality:
```bash
# Test on a site with forms (like httpbin.org/forms/post)
python webscrape.py https://httpbin.org/forms/post --security

# Test spider mode with security analysis
python webscrape.py https://example.com --spider --security --depth 2
```

### Testing the Script
Test with a sample URL:
```bash
echo "https://example.com" | python webscrape.py
```

## Development Notes

- The script supports both interactive and command-line modes
- Comprehensive URL validation and error handling throughout
- Browser-like User-Agent headers are sent to avoid being blocked by websites
- All relative URLs are converted to absolute URLs for better usability
- Duplicate links and emails are automatically removed using sets
- Console output is organized into clear sections with counts
- HTML output creates professional, interactive reports with tree structure
- Auto-generated filenames include domain and timestamp for easy organization
- The script handles timeouts, network errors, and keyboard interruptions gracefully
- Email extraction uses robust regex patterns and multiple detection methods
- Link extraction covers all major HTML elements that can contain URLs
- HTML reports include responsive design and work on all devices

### Security Analysis Features (v2.2.0+)
- **IDOR Detection**: Automatically identifies 25+ common parameter patterns that may be vulnerable to Insecure Direct Object Reference attacks
- **Injection Analysis**: Detects potential SQL injection, XSS, Command injection, Path traversal, and LDAP injection vulnerabilities based on field names and contexts
- **Form Security Assessment**: Analyzes forms for CSRF protection, file upload capabilities, and hidden input manipulation risks
- **AJAX Endpoint Discovery**: Extracts JavaScript AJAX endpoints using regex patterns for jQuery, Fetch API, XMLHttpRequest, and Axios
- **Risk Scoring**: Calculates comprehensive security risk scores with High (7-10 points), Medium (3-5 points), and Low (2 points) categorization
- **Testing Recommendations**: Provides specific testing suggestions for each discovered vulnerability type
- **Ethical Guidelines**: Includes built-in warnings and documentation about responsible security testing practices
- **Report Integration**: Security findings are seamlessly integrated into both console output and HTML reports with color-coding and detailed explanations
