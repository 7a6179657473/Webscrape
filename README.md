# Webscrape 🕷️

A comprehensive Python web scraping utility that extracts all links and email addresses from webpages. This project supports both single-page scraping and advanced spider crawling with multiple levels of depth.

## Features

### 🔍 Single Page Scraping
- Extract all types of links (anchor tags, CSS, images, scripts, iframes)
- Find email addresses using regex patterns and mailto links
- Convert relative URLs to absolute URLs
- Generate interactive HTML reports with tree structure
- Browser-like headers to avoid being blocked

### 🕷️ Spider Crawling
- Multi-level crawling following links up to specified depth
- Same-domain or cross-domain crawling options
- Configurable exclude patterns for unwanted URLs
- Respectful crawling with customizable delays
- Comprehensive HTML reports for all crawled pages
- Real-time progress tracking and statistics

### 🛡️ Security Features
- URL validation and sanitization
- Path traversal prevention
- XSS protection in HTML output
- Safe filename handling
- Timeout protection for requests

## Installation

### Prerequisites
- Python 3.11.9 or higher
- pip (Python package installer)

### Dependencies
Install the required packages:

```bash
pip install requests beautifulsoup4
```

Or install from the requirements file:

```bash
pip install -r requirements.txt
```

## Usage

### Single Page Scraping

**Interactive mode** (prompts for URL):
```bash
python webscrape.py
```

**Command line with URL:**
```bash
python webscrape.py https://example.com
```

**Save results to HTML file:**
```bash
# Auto-generate filename
python webscrape.py https://example.com -o

# Custom filename
python webscrape.py https://example.com -o results.html
```

### Spider Crawling

**Basic spider crawling:**
```bash
# Crawl with depth of 2 levels
python webscrape.py https://example.com --spider --depth 2

# Stay on same domain only
python webscrape.py https://example.com --spider --same-domain

# Allow external domains
python webscrape.py https://example.com --spider --all-domains
```

**Advanced spider options:**
```bash
# Exclude specific patterns
python webscrape.py https://example.com --spider --exclude "blog" "admin" "login"

# Custom delay between requests (respectful crawling)
python webscrape.py https://example.com --spider --delay 2.0

# Save spider results to HTML
python webscrape.py https://example.com --spider --depth 3 -o spider_results.html
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `url` | Target URL to scrape (optional, will prompt if not provided) |
| `-o, --output` | Save results to HTML file (auto-generates filename if no name provided) |
| `--spider` | Enable spider mode for multi-page crawling |
| `--depth` | Maximum crawl depth (default: 2) |
| `--same-domain` | Only follow links on same domain (default: True) |
| `--all-domains` | Allow following external domain links |
| `--exclude` | Regex patterns to exclude from crawling |
| `--delay` | Delay between requests in seconds (default: 1.0) |
| `--help` | Show detailed help and usage examples |

## Output Formats

### Console Output
- Organized sections with clear headings
- Numbered lists of links and emails
- Summary statistics
- Real-time crawling progress (spider mode)

### HTML Reports
- Professional, responsive design
- Interactive tree structure organized by domain
- Clickable links and mailto addresses
- Summary statistics and timestamps
- Mobile-friendly interface
- Collapsible domain groups

### Auto-generated Filenames
When using `-o` without specifying a filename:
- Single page: `webscrape_example.com_20250915_143022.html`
- Spider mode: `spider_example.com_20250915_143022.html`

## Project Structure

```
Webscrape/
├── README.md          # This file
├── WARP.md           # Development guidance for Warp terminal
├── webscrape.py      # Main scraping script
├── requirements.txt  # Python dependencies
└── .gitignore        # Git ignore patterns
```

## Key Functions

- **`extract_links(soup, base_url)`** - Extracts all types of links from HTML
- **`extract_emails(soup, page_text)`** - Finds email addresses using multiple methods
- **`spider_website()`** - Advanced multi-page crawling with depth control
- **`validate_url(url)`** - Security validation for URLs
- **`generate_html_tree()`** - Creates interactive HTML reports
- **`generate_spider_html_report()`** - Comprehensive spider crawl reports

## Security Considerations

- Only HTTP and HTTPS URLs are allowed
- URL length limits prevent abuse
- Filename sanitization prevents path traversal attacks
- HTML content is properly escaped to prevent XSS
- Respectful crawling with delays between requests
- Timeout protection prevents hanging requests

## Examples

### Extract All Links from a Website
```bash
python webscrape.py https://python.org
```

### Spider Crawl a Blog (Stay on Same Domain)
```bash
python webscrape.py https://blog.example.com --spider --depth 3 --exclude "tag" "category"
```

### Generate Comprehensive HTML Report
```bash
python webscrape.py https://news.ycombinator.com --spider --depth 2 -o hn_crawl.html
```

## Author

Created by **zayets** @ [https://github.com/7a6179657473](https://github.com/7a6179657473)

Written in Python with ❤️

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## License

This project is open source and available under the MIT License.
