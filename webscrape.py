## created by zayets @ https://github.com/7a6179657473
# written in python

import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
import sys
import argparse
from datetime import datetime
import os

def extract_links(soup, base_url):
    """Extract all links from the webpage, including various sources."""
    links = set()  # Use set to avoid duplicates
    
    # Extract from <a> tags with href
    for link in soup.find_all('a', href=True):
        href = link['href'].strip()
        if href:
            # Convert relative URLs to absolute
            absolute_url = urljoin(base_url, href)
            links.add(absolute_url)
    
    # Extract from <link> tags (CSS, favicons, etc.)
    for link in soup.find_all('link', href=True):
        href = link['href'].strip()
        if href:
            absolute_url = urljoin(base_url, href)
            links.add(absolute_url)
    
    # Extract from <img> tags with src
    for img in soup.find_all('img', src=True):
        src = img['src'].strip()
        if src:
            absolute_url = urljoin(base_url, src)
            links.add(absolute_url)
    
    # Extract from <script> tags with src
    for script in soup.find_all('script', src=True):
        src = script['src'].strip()
        if src:
            absolute_url = urljoin(base_url, src)
            links.add(absolute_url)
    
    # Extract from <iframe> tags with src
    for iframe in soup.find_all('iframe', src=True):
        src = iframe['src'].strip()
        if src:
            absolute_url = urljoin(base_url, src)
            links.add(absolute_url)
    
    return sorted(links)

def extract_emails(soup, page_text):
    """Extract all email addresses from the webpage."""
    emails = set()  # Use set to avoid duplicates
    
    # Regex pattern for email addresses
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    # Extract emails from page text
    found_emails = re.findall(email_pattern, page_text)
    emails.update(found_emails)
    
    # Extract emails from mailto links
    for link in soup.find_all('a', href=True):
        href = link['href']
        if href.startswith('mailto:'):
            email = href.replace('mailto:', '').split('?')[0]  # Remove query parameters
            if re.match(email_pattern, email):
                emails.add(email)
    
    # Extract emails from data attributes and other common places
    for element in soup.find_all(attrs={"data-email": True}):
        email = element.get('data-email')
        if email and re.match(email_pattern, email):
            emails.add(email)
    
    return sorted(emails)

def generate_html_tree(url, links, emails, output_file):
    """Generate an HTML file with a tree visualization of links and emails."""
    
    # Organize links by domain for tree structure
    link_tree = {}
    for link in links:
        parsed = urlparse(link)
        domain = parsed.netloc or 'local'
        if domain not in link_tree:
            link_tree[domain] = []
        link_tree[domain].append(link)
    
    # Generate HTML content
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Scraping Results - {urlparse(url).netloc}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #e0e0e0;
        }}
        .header h1 {{
            color: #333;
            margin-bottom: 10px;
        }}
        .source-url {{
            color: #666;
            font-size: 18px;
            word-break: break-all;
        }}
        .timestamp {{
            color: #999;
            font-size: 14px;
            margin-top: 10px;
        }}
        .summary {{
            display: flex;
            justify-content: center;
            gap: 40px;
            margin: 20px 0;
            padding: 20px;
            background-color: #f8f9fa;
            border-radius: 8px;
        }}
        .summary-item {{
            text-align: center;
        }}
        .summary-number {{
            font-size: 28px;
            font-weight: bold;
            color: #007bff;
        }}
        .summary-label {{
            color: #666;
            font-size: 14px;
        }}
        .section {{
            margin: 30px 0;
        }}
        .section-title {{
            font-size: 24px;
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #ddd;
        }}
        .tree {{
            margin-left: 20px;
        }}
        .domain-group {{
            margin-bottom: 25px;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            overflow: hidden;
        }}
        .domain-header {{
            background-color: #f8f9fa;
            padding: 12px 15px;
            font-weight: bold;
            color: #495057;
            border-bottom: 1px solid #e0e0e0;
            cursor: pointer;
            transition: background-color 0.2s;
        }}
        .domain-header:hover {{
            background-color: #e9ecef;
        }}
        .domain-header::before {{
            content: '▼ ';
            font-size: 12px;
        }}
        .domain-content {{
            padding: 0;
        }}
        .link-item, .email-item {{
            padding: 10px 15px;
            border-bottom: 1px solid #f0f0f0;
            transition: background-color 0.2s;
        }}
        .link-item:hover, .email-item:hover {{
            background-color: #f8f9fa;
        }}
        .link-item:last-child, .email-item:last-child {{
            border-bottom: none;
        }}
        .link-item a {{
            color: #007bff;
            text-decoration: none;
            word-break: break-all;
        }}
        .link-item a:hover {{
            text-decoration: underline;
        }}
        .email-list {{
            background-color: white;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            overflow: hidden;
        }}
        .no-results {{
            text-align: center;
            color: #999;
            font-style: italic;
            padding: 40px;
        }}
        .link-count {{
            background-color: #6c757d;
            color: white;
            font-size: 12px;
            padding: 2px 8px;
            border-radius: 12px;
            margin-left: 10px;
        }}
        @media (max-width: 768px) {{
            .summary {{
                flex-direction: column;
                gap: 20px;
            }}
            .container {{
                padding: 15px;
            }}
        }}
    </style>
    <script>
        function toggleDomain(element) {{
            const content = element.nextElementSibling;
            const arrow = element.querySelector('::before');
            if (content.style.display === 'none') {{
                content.style.display = 'block';
                element.style.setProperty('--arrow', '"▼ "');
            }} else {{
                content.style.display = 'none';
                element.style.setProperty('--arrow', '"▶ "');
            }}
        }}
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🕷️ Web Scraping Results</h1>
            <div class="source-url">{url}</div>
            <div class="timestamp">Scraped on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}</div>
        </div>
        
        <div class="summary">
            <div class="summary-item">
                <div class="summary-number">{len(links)}</div>
                <div class="summary-label">Links Found</div>
            </div>
            <div class="summary-item">
                <div class="summary-number">{len(emails)}</div>
                <div class="summary-label">Emails Found</div>
            </div>
            <div class="summary-item">
                <div class="summary-number">{len(link_tree)}</div>
                <div class="summary-label">Domains</div>
            </div>
        </div>
"""
    
    # Add links section
    if links:
        html_content += """
        <div class="section">
            <h2 class="section-title">🔗 Links by Domain</h2>
            <div class="tree">
"""
        
        for domain, domain_links in sorted(link_tree.items()):
            html_content += f"""
                <div class="domain-group">
                    <div class="domain-header" onclick="toggleDomain(this)">
                        {domain} <span class="link-count">{len(domain_links)}</span>
                    </div>
                    <div class="domain-content">
"""
            
            for link in sorted(domain_links):
                html_content += f"""
                        <div class="link-item">
                            <a href="{link}" target="_blank">{link}</a>
                        </div>
"""
            
            html_content += """
                    </div>
                </div>
"""
        
        html_content += """
            </div>
        </div>
"""
    else:
        html_content += """
        <div class="section">
            <h2 class="section-title">🔗 Links</h2>
            <div class="no-results">No links found on this page.</div>
        </div>
"""
    
    # Add emails section
    if emails:
        html_content += """
        <div class="section">
            <h2 class="section-title">📧 Email Addresses</h2>
            <div class="email-list">
"""
        
        for email in emails:
            html_content += f"""
                <div class="email-item">
                    <a href="mailto:{email}">{email}</a>
                </div>
"""
        
        html_content += """
            </div>
        </div>
"""
    else:
        html_content += """
        <div class="section">
            <h2 class="section-title">📧 Email Addresses</h2>
            <div class="no-results">No email addresses found on this page.</div>
        </div>
"""
    
    html_content += """
    </div>
</body>
</html>
"""
    
    # Write HTML file
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return True
    except Exception as e:
        print(f"Error writing HTML file: {e}")
        return False

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Web scraper that extracts links and email addresses from webpages.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python webscrape.py                           # Interactive mode
  python webscrape.py https://example.com       # Command line URL
  python webscrape.py https://example.com -o results.html  # Save to HTML
  python webscrape.py https://example.com -o    # Auto-generate filename
"""
    )
    
    parser.add_argument('url', nargs='?', help='URL to scrape (if not provided, will prompt for input)')
    parser.add_argument('-o', '--output', nargs='?', const='auto', 
                       help='Save results to HTML file. Use without filename to auto-generate.')
    
    return parser.parse_args()

def main():
    try:
        args = parse_arguments()
        
        # Get URL from command line or prompt user
        if args.url:
            url = args.url.strip()
        else:
            url = input('Enter the domain (with https/http schema): ').strip()
        
        # Validate URL format
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            print("Error: Please provide a valid URL with http:// or https://")
            sys.exit(1)
        
        print(f"\nFetching content from: {url}")
        
        # Add headers to appear more like a real browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # Raise an exception for bad status codes
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract links
        print("\n=== EXTRACTING LINKS ===")
        links = extract_links(soup, url)
        
        if links:
            print(f"Found {len(links)} unique links:")
            for i, link in enumerate(links, 1):
                print(f"{i:3d}. {link}")
        else:
            print("No links found on this page.")
        
        # Extract emails
        print("\n=== EXTRACTING EMAIL ADDRESSES ===")
        emails = extract_emails(soup, response.text)
        
        if emails:
            print(f"Found {len(emails)} unique email addresses:")
            for i, email in enumerate(emails, 1):
                print(f"{i:3d}. {email}")
        else:
            print("No email addresses found on this page.")
        
        # Summary
        print(f"\n=== SUMMARY ===")
        print(f"Total links found: {len(links)}")
        print(f"Total emails found: {len(emails)}")
        
        # Generate HTML output if requested
        if args.output:
            if args.output == 'auto':
                # Auto-generate filename based on domain and timestamp
                domain = parsed_url.netloc.replace('www.', '')
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_file = f"webscrape_{domain}_{timestamp}.html"
            else:
                output_file = args.output
            
            print(f"\n=== GENERATING HTML OUTPUT ===")
            print(f"Saving results to: {output_file}")
            
            if generate_html_tree(url, links, emails, output_file):
                print(f"✅ HTML report saved successfully to: {os.path.abspath(output_file)}")
                print(f"Open the file in your browser to view the interactive results.")
            else:
                print("❌ Failed to save HTML report.")
        
    except requests.exceptions.RequestException as e:
        print(f"Error fetching the webpage: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
