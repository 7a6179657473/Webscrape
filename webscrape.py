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
import html
import time
from collections import deque
import threading

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

def validate_url(url):
    """Validate URL to ensure it's safe to request."""
    try:
        parsed = urlparse(url)
        
        # Check for valid scheme
        if parsed.scheme not in ['http', 'https']:
            return False, "Only HTTP and HTTPS URLs are allowed"
        
        # Check for valid netloc (domain)
        if not parsed.netloc:
            return False, "Invalid URL: missing domain"
        
        # Prevent localhost/private IP access (optional security measure)
        # Uncomment these lines for additional security in production
        # if parsed.netloc.lower() in ['localhost', '127.0.0.1', '0.0.0.0']:
        #     return False, "Local URLs are not allowed"
        
        # Check for reasonable URL length
        if len(url) > 2048:
            return False, "URL too long"
        
        return True, "Valid URL"
        
    except Exception as e:
        return False, f"URL validation error: {e}"

def is_same_domain(url1, url2):
    """Check if two URLs belong to the same domain."""
    try:
        domain1 = urlparse(url1).netloc.lower()
        domain2 = urlparse(url2).netloc.lower()
        # Remove 'www.' prefix for comparison
        domain1 = domain1.replace('www.', '')
        domain2 = domain2.replace('www.', '')
        return domain1 == domain2
    except:
        return False

def should_follow_link(url, base_url, same_domain_only=True, exclude_patterns=None):
    """Determine if a link should be followed during spidering."""
    if exclude_patterns is None:
        exclude_patterns = []
    
    try:
        parsed = urlparse(url)
        
        # Skip non-HTTP(S) links
        if parsed.scheme not in ['http', 'https']:
            return False
        
        # Skip if same domain only is enabled and domains don't match
        if same_domain_only and not is_same_domain(url, base_url):
            return False
        
        # Skip common file extensions that aren't web pages
        skip_extensions = {
            '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
            '.zip', '.rar', '.tar', '.gz', '.exe', '.dmg', '.pkg',
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv',
            '.css', '.js', '.xml', '.json', '.rss', '.atom'
        }
        
        path_lower = parsed.path.lower()
        for ext in skip_extensions:
            if path_lower.endswith(ext):
                return False
        
        # Skip URLs matching exclude patterns
        for pattern in exclude_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return False
        
        # Skip common non-content paths
        skip_paths = [
            '/wp-admin', '/admin', '/login', '/logout', '/register',
            '/search', '/tag/', '/category/', '/author/',
            '?print=', '?share=', '?utm_', '#',
            'mailto:', 'tel:', 'ftp:', 'javascript:'
        ]
        
        for skip_path in skip_paths:
            if skip_path in url.lower():
                return False
        
        return True
    except:
        return False

def extract_page_links_only(soup, base_url):
    """Extract only page links (a tags with href) for spidering."""
    links = set()
    
    # Extract from <a> tags with href only (for following links)
    for link in soup.find_all('a', href=True):
        href = link['href'].strip()
        if href:
            # Convert relative URLs to absolute
            absolute_url = urljoin(base_url, href)
            links.add(absolute_url)
    
    return sorted(links)

def spider_website(start_url, max_depth=2, same_domain_only=True, exclude_patterns=None, delay=1.0):
    """Spider through a website following links up to max_depth levels.
    
    Args:
        start_url (str): The starting URL to begin spidering
        max_depth (int): Maximum depth to crawl (0 = only start page, 1 = start + 1 level, etc.)
        same_domain_only (bool): Whether to only follow links on the same domain
        exclude_patterns (list): List of regex patterns to exclude from crawling
        delay (float): Delay between requests in seconds to be respectful
    
    Returns:
        dict: Dictionary with 'pages' (dict of url -> {links, emails}) and 'summary' info
    """
    if exclude_patterns is None:
        exclude_patterns = []
    
    # Data structures for crawling
    visited_urls = set()
    pages_data = {}  # url -> {links: [], emails: [], depth: int}
    url_queue = deque([(start_url, 0)])  # (url, depth)
    
    # Headers to appear more like a real browser
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    print(f"\n🕷️  Starting spider crawl from: {start_url}")
    print(f"📊 Max depth: {max_depth}, Same domain only: {same_domain_only}")
    print(f"⏱️  Delay between requests: {delay}s")
    print("\n" + "="*60)
    
    while url_queue:
        current_url, depth = url_queue.popleft()
        
        # Skip if already visited
        if current_url in visited_urls:
            continue
            
        # Skip if max depth exceeded
        if depth > max_depth:
            continue
        
        print(f"\n[Depth {depth}] Crawling: {current_url}")
        
        try:
            # Validate URL
            is_valid, validation_message = validate_url(current_url)
            if not is_valid:
                print(f"  ❌ Skipped: {validation_message}")
                continue
            
            # Add delay to be respectful to servers
            if visited_urls:  # Don't delay on first request
                time.sleep(delay)
            
            # Make request
            response = requests.get(current_url, headers=headers, timeout=10)
            response.raise_for_status()
            
            # Parse content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract all links and emails for this page
            all_links = extract_links(soup, current_url)
            page_links = extract_page_links_only(soup, current_url)
            emails = extract_emails(soup, response.text)
            
            # Store page data
            pages_data[current_url] = {
                'links': all_links,
                'emails': emails,
                'depth': depth,
                'title': soup.find('title').get_text(strip=True) if soup.find('title') else 'No title',
                'status_code': response.status_code
            }
            
            visited_urls.add(current_url)
            
            print(f"  ✅ Found {len(all_links)} links, {len(emails)} emails")
            
            # Add followable links to queue for next depth level
            if depth < max_depth:
                followable_links = []
                for link in page_links:
                    if (link not in visited_urls and 
                        link not in [url for url, _ in url_queue] and
                        should_follow_link(link, start_url, same_domain_only, exclude_patterns)):
                        url_queue.append((link, depth + 1))
                        followable_links.append(link)
                
                if followable_links:
                    print(f"  📝 Added {len(followable_links)} new URLs to crawl at depth {depth + 1}")
                else:
                    print(f"  📝 No new URLs to follow from this page")
                    
        except requests.exceptions.RequestException as e:
            print(f"  ❌ Request error: {e}")
            continue
        except Exception as e:
            print(f"  ❌ Unexpected error: {e}")
            continue
    
    # Calculate summary statistics
    total_links = set()
    total_emails = set()
    pages_by_depth = {}
    
    for url, data in pages_data.items():
        total_links.update(data['links'])
        total_emails.update(data['emails'])
        depth = data['depth']
        if depth not in pages_by_depth:
            pages_by_depth[depth] = 0
        pages_by_depth[depth] += 1
    
    summary = {
        'total_pages': len(pages_data),
        'total_unique_links': len(total_links),
        'total_unique_emails': len(total_emails),
        'max_depth_reached': max(data['depth'] for data in pages_data.values()) if pages_data else 0,
        'pages_by_depth': pages_by_depth,
        'start_url': start_url,
        'crawl_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    print("\n" + "="*60)
    print(f"🎉 Spider crawl completed!")
    print(f"📊 Total pages crawled: {summary['total_pages']}")
    print(f"🔗 Total unique links found: {summary['total_unique_links']}")
    print(f"📧 Total unique emails found: {summary['total_unique_emails']}")
    print(f"📏 Max depth reached: {summary['max_depth_reached']}")
    
    return {
        'pages': pages_data,
        'summary': summary
    }

def sanitize_filename(filename):
    """Sanitize filename to prevent path traversal attacks."""
    # Remove any path separators and dangerous characters
    import re
    # Remove path separators and potentially dangerous characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove any path traversal attempts
    filename = os.path.basename(filename)
    # Ensure filename is not empty and has reasonable length
    if not filename or filename.startswith('.'):
        filename = 'webscrape_output.html'
    # Limit filename length
    if len(filename) > 100:
        name, ext = os.path.splitext(filename)
        filename = name[:96] + ext
    return filename

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
            <div class="source-url">{html.escape(url)}</div>
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
                        {html.escape(domain)} <span class="link-count">{len(domain_links)}</span>
                    </div>
                    <div class="domain-content">
"""
            
            for link in sorted(domain_links):
                html_content += f"""
                        <div class="link-item">
                            <a href="{html.escape(link)}" target="_blank">{html.escape(link)}</a>
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
                    <a href="mailto:{html.escape(email)}">{html.escape(email)}</a>
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

def generate_spider_html_report(spider_results, output_file):
    """Generate an HTML report for spider crawling results."""
    pages_data = spider_results['pages']
    summary = spider_results['summary']
    
    # Organize all links and emails from all pages
    all_links_by_domain = {}
    all_emails = set()
    
    for url, data in pages_data.items():
        all_emails.update(data['emails'])
        for link in data['links']:
            parsed = urlparse(link)
            domain = parsed.netloc or 'local'
            if domain not in all_links_by_domain:
                all_links_by_domain[domain] = set()
            all_links_by_domain[domain].add(link)
    
    # Convert sets to sorted lists
    for domain in all_links_by_domain:
        all_links_by_domain[domain] = sorted(list(all_links_by_domain[domain]))
    all_emails = sorted(list(all_emails))
    
    # Generate HTML content
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Spider Crawl Results - {urlparse(summary['start_url']).netloc}</title>
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
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
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
        .pages-section {{
            margin: 30px 0;
        }}
        .page-item {{
            margin-bottom: 20px;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            overflow: hidden;
        }}
        .page-header {{
            background-color: #f8f9fa;
            padding: 12px 15px;
            border-bottom: 1px solid #e0e0e0;
            cursor: pointer;
        }}
        .page-title {{
            font-weight: bold;
            color: #333;
            margin-bottom: 5px;
        }}
        .page-url {{
            color: #666;
            font-size: 14px;
            word-break: break-all;
        }}
        .page-meta {{
            color: #999;
            font-size: 12px;
            margin-top: 5px;
        }}
        .page-content {{
            padding: 15px;
            display: none;
        }}
        .page-content.active {{
            display: block;
        }}
        .section-title {{
            font-size: 24px;
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #ddd;
        }}
        .domain-group, .email-list {{
            margin-bottom: 15px;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            overflow: hidden;
        }}
        .domain-header {{
            background-color: #f8f9fa;
            padding: 10px 15px;
            font-weight: bold;
            color: #495057;
            border-bottom: 1px solid #e0e0e0;
        }}
        .link-item, .email-item {{
            padding: 8px 15px;
            border-bottom: 1px solid #f0f0f0;
        }}
        .link-item:hover, .email-item:hover {{
            background-color: #f8f9fa;
        }}
        .link-item:last-child, .email-item:last-child {{
            border-bottom: none;
        }}
        .link-item a, .email-item a {{
            color: #007bff;
            text-decoration: none;
            word-break: break-all;
        }}
        .link-item a:hover, .email-item a:hover {{
            text-decoration: underline;
        }}
        .link-count, .email-count {{
            background-color: #6c757d;
            color: white;
            font-size: 12px;
            padding: 2px 8px;
            border-radius: 12px;
            margin-left: 10px;
        }}
        .depth-badge {{
            background-color: #17a2b8;
            color: white;
            font-size: 11px;
            padding: 2px 6px;
            border-radius: 10px;
            margin-left: 10px;
        }}
        .no-results {{
            text-align: center;
            color: #999;
            font-style: italic;
            padding: 40px;
        }}
        @media (max-width: 768px) {{
            .container {{
                padding: 15px;
            }}
        }}
    </style>
    <script>
        function togglePage(element) {{
            const content = element.nextElementSibling;
            content.classList.toggle('active');
        }}
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🕷️ Spider Crawl Results</h1>
            <div class="source-url">{html.escape(summary['start_url'])}</div>
            <div class="timestamp">Crawled on {summary['crawl_timestamp']}</div>
        </div>
        
        <div class="summary">
            <div class="summary-item">
                <div class="summary-number">{summary['total_pages']}</div>
                <div class="summary-label">Pages Crawled</div>
            </div>
            <div class="summary-item">
                <div class="summary-number">{summary['total_unique_links']}</div>
                <div class="summary-label">Unique Links</div>
            </div>
            <div class="summary-item">
                <div class="summary-number">{summary['total_unique_emails']}</div>
                <div class="summary-label">Unique Emails</div>
            </div>
            <div class="summary-item">
                <div class="summary-number">{summary['max_depth_reached']}</div>
                <div class="summary-label">Max Depth</div>
            </div>
            <div class="summary-item">
                <div class="summary-number">{len(all_links_by_domain)}</div>
                <div class="summary-label">Domains</div>
            </div>
        </div>
"""
    
    # Add pages section
    if pages_data:
        html_content += """
        <div class="pages-section">
            <h2 class="section-title">📄 Crawled Pages</h2>
"""
        
        # Sort pages by depth, then by URL
        sorted_pages = sorted(pages_data.items(), key=lambda x: (x[1]['depth'], x[0]))
        
        for url, data in sorted_pages:
            html_content += f"""
            <div class="page-item">
                <div class="page-header" onclick="togglePage(this)">
                    <div class="page-title">{html.escape(data['title'])}</div>
                    <div class="page-url">{html.escape(url)}</div>
                    <div class="page-meta">
                        Depth: {data['depth']} | Links: {len(data['links'])} | Emails: {len(data['emails'])}
                        <span class="depth-badge">Depth {data['depth']}</span>
                    </div>
                </div>
                <div class="page-content">
                    <strong>Page Title:</strong> {html.escape(data['title'])}<br>
                    <strong>Status Code:</strong> {data['status_code']}<br>
                    <strong>Links Found:</strong> {len(data['links'])}<br>
                    <strong>Emails Found:</strong> {len(data['emails'])}<br>
                </div>
            </div>
"""
        
        html_content += """
        </div>
"""
    
    # Add aggregated links section
    if all_links_by_domain:
        html_content += """
        <div class="section">
            <h2 class="section-title">🔗 All Links by Domain</h2>
"""
        
        for domain, domain_links in sorted(all_links_by_domain.items()):
            html_content += f"""
            <div class="domain-group">
                <div class="domain-header">
                    {html.escape(domain)} <span class="link-count">{len(domain_links)}</span>
                </div>
"""
            
            for link in domain_links:
                html_content += f"""
                <div class="link-item">
                    <a href="{html.escape(link)}" target="_blank">{html.escape(link)}</a>
                </div>
"""
            
            html_content += """
            </div>
"""
        
        html_content += """
        </div>
"""
    
    # Add emails section
    if all_emails:
        html_content += f"""
        <div class="section">
            <h2 class="section-title">📧 All Email Addresses</h2>
            <div class="email-list">
                <div class="domain-header">
                    Email Addresses <span class="email-count">{len(all_emails)}</span>
                </div>
"""
        
        for email in all_emails:
            html_content += f"""
                <div class="email-item">
                    <a href="mailto:{html.escape(email)}">{html.escape(email)}</a>
                </div>
"""
        
        html_content += """
            </div>
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
        print(f"Error writing spider HTML file: {e}")
        return False

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Web scraper that extracts links and email addresses from webpages. Supports single page scraping and spider crawling.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single page scraping
  python webscrape.py                           # Interactive mode
  python webscrape.py https://example.com       # Command line URL
  python webscrape.py https://example.com -o results.html  # Save to HTML
  python webscrape.py https://example.com -o    # Auto-generate filename
  
  # Spider crawling
  python webscrape.py https://example.com --spider --depth 2  # Spider with depth 2
  python webscrape.py https://example.com --spider --depth 3 --same-domain  # Stay on same domain
  python webscrape.py https://example.com --spider --exclude "blog" "admin"  # Exclude patterns
  python webscrape.py https://example.com --spider --delay 2.0 -o spider_results.html  # Custom delay
"""
    )
    
    parser.add_argument('url', nargs='?', help='URL to scrape (if not provided, will prompt for input)')
    parser.add_argument('-o', '--output', nargs='?', const='auto', 
                       help='Save results to HTML file. Use without filename to auto-generate.')
    
    # Spider-specific arguments
    parser.add_argument('--spider', action='store_true',
                       help='Enable spider mode to crawl multiple pages by following links')
    parser.add_argument('--depth', type=int, default=2, 
                       help='Maximum crawl depth for spider mode (default: 2)')
    parser.add_argument('--same-domain', action='store_true', default=True,
                       help='Only follow links on the same domain (default: True)')
    parser.add_argument('--all-domains', action='store_true',
                       help='Allow following links to external domains (overrides --same-domain)')
    parser.add_argument('--exclude', nargs='*', default=[],
                       help='Regex patterns to exclude from crawling (e.g., "blog" "admin")')
    parser.add_argument('--delay', type=float, default=1.0,
                       help='Delay between requests in seconds (default: 1.0)')
    
    return parser.parse_args()

def main():
    try:
        args = parse_arguments()
        
        # Get URL from command line or prompt user
        if args.url:
            url = args.url.strip()
        else:
            url = input('Enter the domain (with https/http schema): ').strip()
        
        # Validate URL format and security
        is_valid, validation_message = validate_url(url)
        if not is_valid:
            print(f"Error: {validation_message}")
            sys.exit(1)
        
        parsed_url = urlparse(url)
        
        # Handle spider mode vs single page mode
        if args.spider:
            # Spider mode: crawl multiple pages
            same_domain_only = not args.all_domains  # If --all-domains is set, allow external domains
            
            print(f"\n🕷️  SPIDER MODE ENABLED")
            print(f"Starting URL: {url}")
            print(f"Max depth: {args.depth}")
            print(f"Same domain only: {same_domain_only}")
            print(f"Exclude patterns: {args.exclude if args.exclude else 'None'}")
            print(f"Request delay: {args.delay}s")
            
            # Run spider crawl
            spider_results = spider_website(
                start_url=url,
                max_depth=args.depth,
                same_domain_only=same_domain_only,
                exclude_patterns=args.exclude,
                delay=args.delay
            )
            
            # Generate HTML output if requested
            if args.output:
                if args.output == 'auto':
                    # Auto-generate filename based on domain and timestamp
                    domain = parsed_url.netloc.replace('www.', '')
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    output_file = f"spider_{domain}_{timestamp}.html"
                else:
                    output_file = sanitize_filename(args.output)
                
                print(f"\n=== GENERATING SPIDER HTML REPORT ===")
                print(f"Saving results to: {output_file}")
                
                if generate_spider_html_report(spider_results, output_file):
                    print(f"✅ Spider HTML report saved successfully to: {os.path.abspath(output_file)}")
                    print(f"Open the file in your browser to view the interactive results.")
                else:
                    print("❌ Failed to save spider HTML report.")
            
        else:
            # Single page mode: original functionality
            print(f"\n📄 SINGLE PAGE MODE")
            print(f"Fetching content from: {url}")
            
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
                    output_file = sanitize_filename(args.output)
                
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
