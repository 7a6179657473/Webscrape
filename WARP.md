# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

This is a comprehensive Python web scraping utility that extracts all links and email addresses from a given webpage. The project consists of a single Python script that uses requests and BeautifulSoup for web scraping functionality with enhanced link detection and email extraction capabilities.

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

## Dependencies

The project requires two main Python packages:
- **requests** (v2.32.3+): For HTTP requests and webpage fetching
- **beautifulsoup4** (v4.13.4+): For HTML parsing and link/email extraction

Built-in Python modules used:
- **re**: For regex pattern matching (email extraction)
- **urllib.parse**: For URL parsing and joining
- **sys**: For system operations and exit handling
- **argparse**: For command-line argument parsing
- **datetime**: For timestamp generation in HTML reports
- **os**: For file path operations

Python version: 3.11.9+

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

### Installing Dependencies
Since there's no requirements.txt file, install dependencies manually:
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
webscrape_example.com_20250911_002023.html
```

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
