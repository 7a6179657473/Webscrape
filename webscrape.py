#!/usr/bin/env python3
"""
Webscrape - A comprehensive web scraping utility with spider crawling capabilities.

This module provides functionality to:
- Extract all types of links from webpages (anchor tags, CSS, images, scripts, iframes)
- Find email addresses using regex patterns and HTML parsing
- Perform single-page scraping or multi-level spider crawling
- Generate interactive HTML reports with professional styling
- Handle security considerations and respectful crawling
- Identify IDOR (Insecure Direct Object Reference) vulnerabilities
- Detect potential injection points (SQL, XSS, Command, Path Traversal)
- Analyze form inputs and hidden parameters
- Extract AJAX endpoints from JavaScript code
- Generate comprehensive security assessment reports

Author: zayets @ https://github.com/7a6179657473
Version: 2.2.0 - Security Analysis Edition
Python Version: 3.11+
License: MIT
"""

__version__ = "2.2.0"
__author__ = "zayets"
__email__ = "zayets@github.com"
__license__ = "MIT"

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

# Constants for configuration
DEFAULT_TIMEOUT = 10  # seconds
MAX_URL_LENGTH = 2048  # characters
MAX_FILENAME_LENGTH = 100  # characters
DEFAULT_SPIDER_DEPTH = 2
DEFAULT_SPIDER_DELAY = 1.0  # seconds

# Security constants
MAX_SPIDER_PAGES = 1000  # Maximum pages to crawl
MAX_SPIDER_DEPTH_LIMIT = 10  # Maximum depth allowed for security
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB max file size
MAX_REGEX_PATTERN_LENGTH = 100  # Maximum regex pattern length

# User-Agent string to appear more like a real browser
DEFAULT_USER_AGENT = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/91.0.4472.124 Safari/537.36')

# Email regex pattern (RFC 5322 compliant)
EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

# File extensions to skip during spider crawling
SKIP_EXTENSIONS = {
    '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
    '.zip', '.rar', '.tar', '.gz', '.exe', '.dmg', '.pkg',
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv',
    '.css', '.js', '.xml', '.json', '.rss', '.atom'
}

def extract_links(soup, base_url):
    """Extract all links from the webpage, including various HTML elements.
    
    This function searches for links in multiple HTML elements:
    - <a href> tags (anchor links)
    - <link href> tags (CSS, favicons, etc.)
    - <img src> tags (images)
    - <script src> tags (JavaScript files)
    - <iframe src> tags (embedded content)
    
    Args:
        soup (BeautifulSoup): Parsed HTML content
        base_url (str): Base URL for converting relative links to absolute
        
    Returns:
        list: Sorted list of unique absolute URLs found on the page
    """
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
    """Extract all email addresses from the webpage using multiple methods.
    
    This function finds email addresses by:
    - Regex pattern matching on page text content
    - Parsing mailto: links in anchor tags
    - Checking data-email attributes in HTML elements
    
    Args:
        soup (BeautifulSoup): Parsed HTML content
        page_text (str): Raw text content of the webpage
        
    Returns:
        list: Sorted list of unique email addresses found on the page
    """
    emails = set()  # Use set to avoid duplicates
    
    # Use the globally defined email pattern
    email_pattern = EMAIL_PATTERN
    
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

def extract_input_parameters(soup, base_url):
    """Extract URLs with query parameters and form inputs for IDOR/injection testing.
    
    This function identifies potential security testing targets by finding:
    - URLs with query parameters (GET parameters)
    - HTML forms with input fields
    - Input fields with IDs, names, and types
    - Hidden inputs that might contain sensitive data
    - AJAX endpoints from JavaScript
    
    Args:
        soup (BeautifulSoup): Parsed HTML content
        base_url (str): Base URL for converting relative URLs to absolute
        
    Returns:
        dict: Dictionary containing categorized input findings
    """
    results = {
        'parameterized_urls': [],  # URLs with query parameters
        'forms': [],              # Form elements with inputs
        'input_fields': [],       # Individual input fields
        'potential_ids': [],      # Parameters that might be IDORs
        'ajax_endpoints': []      # Potential AJAX endpoints
    }
    
    # Extract URLs with query parameters from links
    for link in soup.find_all('a', href=True):
        href = link['href'].strip()
        if href and '?' in href:
            absolute_url = urljoin(base_url, href)
            parsed_url = urlparse(absolute_url)
            if parsed_url.query:
                # Parse query parameters
                from urllib.parse import parse_qs
                params = parse_qs(parsed_url.query)
                
                param_info = {
                    'url': absolute_url,
                    'parameters': {},
                    'link_text': link.get_text(strip=True)[:100],  # Truncate for readability
                    'potential_idor': False
                }
                
                # Analyze each parameter
                for param_name, param_values in params.items():
                    param_info['parameters'][param_name] = param_values[0] if param_values else ''
                    
                    # Check if parameter might be an IDOR target
                    if is_potential_idor_parameter(param_name, param_values[0] if param_values else ''):
                        param_info['potential_idor'] = True
                        results['potential_ids'].append({
                            'url': absolute_url,
                            'parameter': param_name,
                            'value': param_values[0] if param_values else '',
                            'context': link.get_text(strip=True)[:50]
                        })
                
                results['parameterized_urls'].append(param_info)
    
    # Extract form elements and their inputs
    for form in soup.find_all('form'):
        form_info = {
            'action': urljoin(base_url, form.get('action', '')),
            'method': form.get('method', 'GET').upper(),
            'inputs': [],
            'has_file_upload': False,
            'has_hidden_inputs': False,
            'potential_vulnerabilities': []
        }
        
        # Extract all input fields from the form
        for input_elem in form.find_all(['input', 'textarea', 'select']):
            input_info = {
                'tag': input_elem.name,
                'type': input_elem.get('type', 'text'),
                'name': input_elem.get('name', ''),
                'id': input_elem.get('id', ''),
                'value': input_elem.get('value', ''),
                'placeholder': input_elem.get('placeholder', ''),
                'required': input_elem.has_attr('required'),
                'pattern': input_elem.get('pattern', ''),
                'max_length': input_elem.get('maxlength', ''),
            }
            
            # Check for specific vulnerability indicators
            if input_info['type'] == 'file':
                form_info['has_file_upload'] = True
                form_info['potential_vulnerabilities'].append('File Upload - Check for unrestricted file types')
            
            if input_info['type'] == 'hidden':
                form_info['has_hidden_inputs'] = True
                if input_info['value']:
                    form_info['potential_vulnerabilities'].append(f'Hidden input with value: {input_info["name"]}={input_info["value"]}')
            
            # Check for potential IDOR parameters in form inputs
            if is_potential_idor_parameter(input_info['name'], input_info['value']):
                results['potential_ids'].append({
                    'url': form_info['action'],
                    'parameter': input_info['name'],
                    'value': input_info['value'],
                    'context': f'Form input ({input_info["type"]})'
                })
            
            # Check for injection-prone input types
            if input_info['type'] in ['text', 'search', 'url', 'email'] or input_elem.name == 'textarea':
                vuln_type = identify_injection_vulnerability_type(input_info['name'], input_info['placeholder'])
                if vuln_type:
                    form_info['potential_vulnerabilities'].append(f'{input_info["name"]}: {vuln_type}')
            
            form_info['inputs'].append(input_info)
            results['input_fields'].append({
                'form_action': form_info['action'],
                'form_method': form_info['method'],
                **input_info
            })
        
        results['forms'].append(form_info)
    
    # Look for potential AJAX endpoints in script tags
    for script in soup.find_all('script'):
        if script.string:
            ajax_urls = extract_ajax_endpoints(script.string, base_url)
            results['ajax_endpoints'].extend(ajax_urls)
    
    return results

def is_potential_idor_parameter(param_name, param_value):
    """Determine if a parameter might be vulnerable to IDOR attacks.
    
    Args:
        param_name (str): Parameter name
        param_value (str): Parameter value
        
    Returns:
        bool: True if parameter might be IDOR-vulnerable
    """
    # Common parameter names that often indicate IDOR vulnerabilities
    idor_indicators = [
        'id', 'user_id', 'userid', 'uid', 'account_id', 'profile_id',
        'doc_id', 'file_id', 'document_id', 'order_id', 'invoice_id',
        'ticket_id', 'message_id', 'post_id', 'comment_id', 'item_id',
        'product_id', 'customer_id', 'client_id', 'reference', 'ref',
        'key', 'token', 'session_id', 'auth_id', 'admin_id', 'member_id'
    ]
    
    param_lower = param_name.lower()
    
    # Check if parameter name matches common IDOR patterns
    for indicator in idor_indicators:
        if indicator in param_lower:
            # Check if value looks like an ID (numeric, UUID, hash)
            if param_value:
                if (param_value.isdigit() or 
                    re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', param_value) or
                    re.match(r'^[a-f0-9]{32}$', param_value) or
                    re.match(r'^[a-f0-9]{40}$', param_value)):
                    return True
            else:
                # Parameter exists but no value - still potential
                return True
    
    return False

def identify_injection_vulnerability_type(field_name, placeholder):
    """Identify potential injection vulnerability types based on field characteristics.
    
    Args:
        field_name (str): Name of the input field
        placeholder (str): Placeholder text of the field
        
    Returns:
        str: Description of potential vulnerability type, or None
    """
    field_lower = field_name.lower()
    placeholder_lower = placeholder.lower() if placeholder else ''
    combined_text = f'{field_lower} {placeholder_lower}'
    
    vulnerabilities = []
    
    # SQL Injection indicators
    sql_indicators = ['search', 'query', 'filter', 'where', 'select', 'username', 'login', 'email']
    if any(indicator in combined_text for indicator in sql_indicators):
        vulnerabilities.append('Potential SQL Injection')
    
    # XSS indicators
    xss_indicators = ['comment', 'message', 'content', 'description', 'text', 'name', 'title']
    if any(indicator in combined_text for indicator in xss_indicators):
        vulnerabilities.append('Potential XSS')
    
    # Command Injection indicators
    cmd_indicators = ['command', 'cmd', 'exec', 'system', 'shell', 'run']
    if any(indicator in combined_text for indicator in cmd_indicators):
        vulnerabilities.append('Potential Command Injection')
    
    # Path Traversal indicators
    path_indicators = ['file', 'path', 'dir', 'folder', 'upload', 'download', 'include']
    if any(indicator in combined_text for indicator in path_indicators):
        vulnerabilities.append('Potential Path Traversal')
    
    # LDAP Injection indicators
    ldap_indicators = ['ldap', 'dn', 'ou', 'cn', 'directory']
    if any(indicator in combined_text for indicator in ldap_indicators):
        vulnerabilities.append('Potential LDAP Injection')
    
    return ', '.join(vulnerabilities) if vulnerabilities else None

def extract_ajax_endpoints(script_content, base_url):
    """Extract potential AJAX endpoints from JavaScript code.
    
    Args:
        script_content (str): JavaScript code content
        base_url (str): Base URL for resolving relative URLs
        
    Returns:
        list: List of potential AJAX endpoints with context
    """
    endpoints = []
    
    # Common AJAX patterns
    ajax_patterns = [
        r'\$\.ajax\([^)]*url[\s]*:[\s]*["\']([^"\'/]+(?:/[^"\']*)*)["\'\']',  # jQuery AJAX
        r'\$\.get\([\s]*["\']([^"\'/]+(?:/[^"\']*)*)["\'\']',  # jQuery GET
        r'\$\.post\([\s]*["\']([^"\'/]+(?:/[^"\']*)*)["\'\']',  # jQuery POST
        r'fetch\([\s]*["\']([^"\'/]+(?:/[^"\']*)*)["\'\']',  # Fetch API
        r'XMLHttpRequest[^)]*open\([^,]*,[\s]*["\']([^"\'/]+(?:/[^"\']*)*)["\'\']',  # XMLHttpRequest
        r'axios\.[a-z]+\([\s]*["\']([^"\'/]+(?:/[^"\']*)*)["\'\']',  # Axios
    ]
    
    for pattern in ajax_patterns:
        matches = re.findall(pattern, script_content, re.IGNORECASE)
        for match in matches:
            absolute_url = urljoin(base_url, match)
            if absolute_url not in [ep['url'] for ep in endpoints]:
                endpoints.append({
                    'url': absolute_url,
                    'type': 'AJAX Endpoint',
                    'method': 'Unknown',
                    'context': 'JavaScript'
                })
    
    return endpoints

def analyze_security_findings(input_data, url):
    """Analyze security findings and categorize vulnerabilities.
    
    Args:
        input_data (dict): Input parameter data from extract_input_parameters
        url (str): Source URL being analyzed
        
    Returns:
        dict: Comprehensive security analysis results
    """
    analysis = {
        'summary': {
            'total_parameterized_urls': len(input_data['parameterized_urls']),
            'total_forms': len(input_data['forms']),
            'total_input_fields': len(input_data['input_fields']),
            'potential_idor_params': len(input_data['potential_ids']),
            'ajax_endpoints': len(input_data['ajax_endpoints']),
            'risk_score': 0
        },
        'high_risk_findings': [],
        'medium_risk_findings': [],
        'low_risk_findings': [],
        'recommendations': []
    }
    
    # Analyze parameterized URLs for IDOR risks
    for param_url in input_data['parameterized_urls']:
        if param_url['potential_idor']:
            finding = {
                'type': 'Potential IDOR Vulnerability',
                'severity': 'HIGH',
                'url': param_url['url'],
                'description': 'URL contains parameters that may be vulnerable to Insecure Direct Object Reference (IDOR) attacks',
                'parameters': list(param_url['parameters'].keys()),
                'test_suggestion': 'Try modifying ID parameters to access other users\' data'
            }
            analysis['high_risk_findings'].append(finding)
            analysis['summary']['risk_score'] += 10
        else:
            # Regular parameterized URL - medium risk
            finding = {
                'type': 'Parameterized URL',
                'severity': 'MEDIUM',
                'url': param_url['url'],
                'description': 'URL accepts parameters that could be tested for injection vulnerabilities',
                'parameters': list(param_url['parameters'].keys()),
                'test_suggestion': 'Test parameters for SQL injection, XSS, and other injection attacks'
            }
            analysis['medium_risk_findings'].append(finding)
            analysis['summary']['risk_score'] += 3
    
    # Analyze forms for various vulnerabilities
    for form in input_data['forms']:
        # High-risk form findings
        if form['has_file_upload']:
            finding = {
                'type': 'File Upload Form',
                'severity': 'HIGH',
                'url': form['action'],
                'description': 'Form allows file uploads - potential for malicious file upload',
                'method': form['method'],
                'test_suggestion': 'Test file upload restrictions, try uploading malicious files (PHP, ASP, etc.)'
            }
            analysis['high_risk_findings'].append(finding)
            analysis['summary']['risk_score'] += 8
        
        if form['has_hidden_inputs']:
            finding = {
                'type': 'Hidden Input Fields',
                'severity': 'MEDIUM',
                'url': form['action'],
                'description': 'Form contains hidden inputs that might be manipulated',
                'method': form['method'],
                'test_suggestion': 'Examine hidden input values and test parameter manipulation'
            }
            analysis['medium_risk_findings'].append(finding)
            analysis['summary']['risk_score'] += 4
        
        # Check for forms without CSRF protection indicators
        has_csrf_token = any(inp['name'].lower() in ['csrf_token', '_token', 'authenticity_token', '_csrf'] 
                           for inp in form['inputs'])
        if not has_csrf_token and len(form['inputs']) > 1:
            finding = {
                'type': 'Potential CSRF Vulnerability',
                'severity': 'MEDIUM',
                'url': form['action'],
                'description': 'Form appears to lack CSRF protection',
                'method': form['method'],
                'test_suggestion': 'Test form submission from external site to check CSRF protection'
            }
            analysis['medium_risk_findings'].append(finding)
            analysis['summary']['risk_score'] += 5
        
        # Analyze individual form vulnerabilities
        for vuln in form['potential_vulnerabilities']:
            if any(high_risk in vuln.lower() for high_risk in ['command injection', 'file upload']):
                severity = 'HIGH'
                score = 7
            elif any(med_risk in vuln.lower() for med_risk in ['sql injection', 'xss']):
                severity = 'MEDIUM'  
                score = 5
            else:
                severity = 'LOW'
                score = 2
            
            finding = {
                'type': 'Input Field Vulnerability',
                'severity': severity,
                'url': form['action'],
                'description': vuln,
                'method': form['method'],
                'test_suggestion': f'Test this input field for {vuln.lower()}'
            }
            
            if severity == 'HIGH':
                analysis['high_risk_findings'].append(finding)
            elif severity == 'MEDIUM':
                analysis['medium_risk_findings'].append(finding)
            else:
                analysis['low_risk_findings'].append(finding)
            
            analysis['summary']['risk_score'] += score
    
    # Analyze AJAX endpoints
    for endpoint in input_data['ajax_endpoints']:
        finding = {
            'type': 'AJAX Endpoint',
            'severity': 'MEDIUM',
            'url': endpoint['url'],
            'description': 'JavaScript AJAX endpoint that may accept parameters',
            'context': endpoint['context'],
            'test_suggestion': 'Test endpoint directly for injection vulnerabilities and authentication bypass'
        }
        analysis['medium_risk_findings'].append(finding)
        analysis['summary']['risk_score'] += 3
    
    # Generate recommendations based on findings
    if analysis['summary']['potential_idor_params'] > 0:
        analysis['recommendations'].append(
            'Implement proper authorization checks for all object references to prevent IDOR attacks'
        )
    
    if analysis['summary']['total_forms'] > 0:
        analysis['recommendations'].extend([
            'Implement CSRF protection for all state-changing forms',
            'Validate and sanitize all user inputs server-side',
            'Use parameterized queries to prevent SQL injection'
        ])
    
    if any(form['has_file_upload'] for form in input_data['forms']):
        analysis['recommendations'].extend([
            'Restrict file upload types and validate file contents',
            'Store uploaded files outside web root and scan for malware',
            'Implement size limits and rate limiting for file uploads'
        ])
    
    if analysis['summary']['ajax_endpoints'] > 0:
        analysis['recommendations'].append(
            'Ensure AJAX endpoints have proper authentication and authorization controls'
        )
    
    # Add general security recommendations
    analysis['recommendations'].extend([
        'Implement Content Security Policy (CSP) headers',
        'Use HTTPS for all sensitive data transmission',
        'Implement proper session management and timeout controls',
        'Regular security testing and vulnerability assessments'
    ])
    
    return analysis

def validate_url(url):
    """Enhanced URL validation with comprehensive SSRF protection.
    
    Security checks performed:
    - Ensures only HTTP/HTTPS schemes are allowed
    - Validates presence of domain (netloc)
    - Blocks localhost and private IP addresses
    - Prevents access to internal network resources
    - Checks for reasonable URL length
    - Resolves hostnames to prevent DNS-based bypasses
    
    Args:
        url (str): URL to validate
        
    Returns:
        tuple: (is_valid: bool, message: str) indicating validation result
    """
    import ipaddress
    import socket
    
    try:
        parsed = urlparse(url)
        
        # Check for valid scheme
        if parsed.scheme not in ['http', 'https']:
            return False, "Only HTTP and HTTPS URLs are allowed"
        
        # Check for valid netloc (domain)
        if not parsed.netloc:
            return False, "Invalid URL: missing domain"
        
        # CRITICAL: Prevent SSRF attacks
        # Block localhost variations
        localhost_patterns = [
            'localhost', '127.0.0.1', '0.0.0.0', '::1',
            '0000:0000:0000:0000:0000:0000:0000:0001',
            '10.0.0.1', '192.168.1.1'  # Common router IPs
        ]
        
        hostname = parsed.netloc.split(':')[0].lower()
        if hostname in localhost_patterns:
            return False, "Local URLs are not allowed for security"
        
        # Block private IP ranges and localhost
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
                return False, "Private/internal IP addresses are not allowed"
            # Block additional dangerous ranges
            if ip in ipaddress.ip_network('169.254.0.0/16'):  # Link-local
                return False, "Link-local addresses are not allowed"
            if ip in ipaddress.ip_network('224.0.0.0/4'):  # Multicast
                return False, "Multicast addresses are not allowed"
        except ValueError:
            # Not an IP address, check if it resolves to private IP
            try:
                resolved_ip = socket.gethostbyname(hostname)
                ip = ipaddress.ip_address(resolved_ip)
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
                    return False, "Domain resolves to private IP address"
                # Block cloud metadata services
                if resolved_ip in ['169.254.169.254', '169.254.1.1']:
                    return False, "Access to cloud metadata services is blocked"
            except (socket.gaierror, ValueError):
                pass  # DNS resolution failed, let it proceed (might be valid external domain)
        
        # Block common internal hostnames
        internal_hosts = ['router', 'gateway', 'printer', 'nas', 'admin', 'management']
        if any(internal in hostname for internal in internal_hosts):
            return False, "Internal hostnames are not allowed"
        
        # Block common dangerous TLDs for internal networks
        dangerous_tlds = ['.local', '.internal', '.corp', '.home', '.lan']
        if any(hostname.endswith(tld) for tld in dangerous_tlds):
            return False, "Internal domain TLDs are not allowed"
        
        # Check for reasonable URL length
        if len(url) > MAX_URL_LENGTH:
            return False, f"URL too long (max {MAX_URL_LENGTH} characters)"
        
        return True, "Valid URL"
        
    except Exception:
        return False, "URL validation failed"  # Don't expose internal errors

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
    """Determine if a link should be followed during spidering with enhanced security."""
    if exclude_patterns is None:
        exclude_patterns = []
    
    # Validate and sanitize regex patterns to prevent ReDoS
    safe_patterns = []
    for pattern in exclude_patterns:
        try:
            # Test with a simple string to catch basic ReDoS
            re.search(pattern, "test", re.IGNORECASE)
            # Limit pattern complexity to prevent ReDoS
            if len(pattern) > MAX_REGEX_PATTERN_LENGTH:
                print(f"Warning: Regex pattern too long, ignoring: {pattern[:50]}...")
                continue
            safe_patterns.append(pattern)
        except re.error:
            print(f"Warning: Invalid regex pattern ignored: {pattern}")
            continue
    
    exclude_patterns = safe_patterns
    
    try:
        parsed = urlparse(url)
        
        # Skip non-HTTP(S) links
        if parsed.scheme not in ['http', 'https']:
            return False
        
        # Skip if same domain only is enabled and domains don't match
        if same_domain_only and not is_same_domain(url, base_url):
            return False
        
        # Skip common file extensions that aren't web pages
        skip_extensions = SKIP_EXTENSIONS
        
        path_lower = parsed.path.lower()
        for ext in skip_extensions:
            if path_lower.endswith(ext):
                return False
        
        # Skip URLs matching exclude patterns (with timeout protection)
        for pattern in exclude_patterns:
            try:
                if re.search(pattern, url, re.IGNORECASE):
                    return False
            except re.error:
                # Skip this pattern if it causes issues
                continue
        
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
    """Spider through a website following links up to max_depth levels with security limits.
    
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
    
    # Security: Limit maximum depth to prevent abuse
    if max_depth > MAX_SPIDER_DEPTH_LIMIT:
        print(f"Warning: Depth limited to {MAX_SPIDER_DEPTH_LIMIT} for security")
        max_depth = MAX_SPIDER_DEPTH_LIMIT
    
    # Data structures for crawling
    visited_urls = set()
    pages_data = {}  # url -> {links: [], emails: [], depth: int}
    url_queue = deque([(start_url, 0)])  # (url, depth)
    pages_crawled = 0  # Track number of pages for security limits
    
    # Headers to appear more like a real browser
    headers = {
        'User-Agent': DEFAULT_USER_AGENT
    }
    
    print(f"\n🕷️  Starting spider crawl from: {start_url}")
    print(f"📊 Max depth: {max_depth}, Same domain only: {same_domain_only}")
    print(f"⏱️  Delay between requests: {delay}s")
    print("\n" + "="*60)
    
    while url_queue and pages_crawled < MAX_SPIDER_PAGES:
        current_url, depth = url_queue.popleft()
        
        # Skip if already visited
        if current_url in visited_urls:
            continue
            
        # Skip if max depth exceeded
        if depth > max_depth:
            continue
        
        # Security: Check if we've hit the page limit
        if pages_crawled >= MAX_SPIDER_PAGES:
            print(f"\n⚠️  Reached maximum page limit ({MAX_SPIDER_PAGES}) for security")
            break
        
        print(f"\n[Depth {depth}] Crawling: {current_url} (Page {pages_crawled + 1}/{MAX_SPIDER_PAGES})")
        
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
            response = requests.get(current_url, headers=headers, timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
            
            # Security: Check response size to prevent memory exhaustion
            if len(response.content) > MAX_FILE_SIZE:
                print(f"  ❌ Skipped: Response too large ({len(response.content):,} bytes, max {MAX_FILE_SIZE:,})")
                continue
            
            # Parse content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract all links and emails for this page
            all_links = extract_links(soup, current_url)
            page_links = extract_page_links_only(soup, current_url)
            emails = extract_emails(soup, response.text)
            
            # Extract security-relevant information if security mode is enabled
            security_data = None
            if hasattr(spider_website, '_security_mode') and spider_website._security_mode:
                security_data = extract_input_parameters(soup, current_url)
            
            # Store page data
            pages_data[current_url] = {
                'links': all_links,
                'emails': emails,
                'depth': depth,
                'title': soup.find('title').get_text(strip=True) if soup.find('title') else 'No title',
                'status_code': response.status_code,
                'security_data': security_data
            }
            
            visited_urls.add(current_url)
            pages_crawled += 1  # Increment page counter
            
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
            print(f"  ❌ Request error: {type(e).__name__}")
            continue
        except Exception:
            print(f"  ❌ Unexpected error occurred")
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
    if len(filename) > MAX_FILENAME_LENGTH:
        name, ext = os.path.splitext(filename)
        filename = name[:MAX_FILENAME_LENGTH-4] + ext
    return filename

def generate_html_tree(url, links, emails, output_file, security_info=None):
    """Generate an interactive HTML report with organized links and emails.
    
    Creates a professional HTML report featuring:
    - Interactive tree structure organized by domain
    - Collapsible domain groups with link counts
    - Clickable links and mailto addresses
    - Summary statistics and timestamps
    - Responsive design for mobile and desktop
    - XSS-safe content escaping
    
    Args:
        url (str): Source URL that was scraped
        links (list): List of links found on the page
        emails (list): List of email addresses found
        output_file (str): Path to save the HTML report
        
    Returns:
        bool: True if file was created successfully, False otherwise
    """
    
    # Security: Check if file exists and warn user
    if os.path.exists(output_file):
        print(f"Warning: File {output_file} already exists and will be overwritten")
    
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
    
    # Add security section if security analysis was performed
    if security_info:
        security_analysis = security_info['security_analysis']
        security_data = security_info['security_data']
        
        html_content += f"""
        <div class="section">
            <h2 class="section-title">🔒 Security Analysis</h2>
            <div class="summary">
                <div class="summary-item">
                    <div class="summary-number">{security_analysis['summary']['risk_score']}</div>
                    <div class="summary-label">Risk Score</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number" style="color: #dc3545;">{len(security_analysis['high_risk_findings'])}</div>
                    <div class="summary-label">High Risk</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number" style="color: #fd7e14;">{len(security_analysis['medium_risk_findings'])}</div>
                    <div class="summary-label">Medium Risk</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number" style="color: #198754;">{len(security_analysis['low_risk_findings'])}</div>
                    <div class="summary-label">Low Risk</div>
                </div>
            </div>
        """
        
        # Add high risk findings
        if security_analysis['high_risk_findings']:
            html_content += """
            <h3 style="color: #dc3545; margin-top: 30px;">🚨 High Risk Findings</h3>
            <div class="email-list">
            """
            for finding in security_analysis['high_risk_findings']:
                html_content += f"""
                <div class="email-item" style="border-left: 4px solid #dc3545;">
                    <strong>{html.escape(finding['type'])}</strong><br>
                    <small style="color: #666;">{html.escape(finding['description'])}</small><br>
                    <small style="color: #007bff;">URL: <a href="{html.escape(finding['url'])}" target="_blank">{html.escape(finding['url'])}</a></small><br>
                    <small style="color: #28a745;">Test: {html.escape(finding['test_suggestion'])}</small>
                </div>
                """
            html_content += "</div>"
        
        # Add medium risk findings (limited)
        if security_analysis['medium_risk_findings']:
            html_content += """
            <h3 style="color: #fd7e14; margin-top: 30px;">⚠️ Medium Risk Findings</h3>
            <div class="email-list">
            """
            for finding in security_analysis['medium_risk_findings'][:10]:  # Limit to 10
                html_content += f"""
                <div class="email-item" style="border-left: 4px solid #fd7e14;">
                    <strong>{html.escape(finding['type'])}</strong><br>
                    <small style="color: #666;">{html.escape(finding['description'])}</small><br>
                    <small style="color: #007bff;">URL: <a href="{html.escape(finding['url'])}" target="_blank">{html.escape(finding['url'])}</a></small><br>
                    <small style="color: #28a745;">Test: {html.escape(finding['test_suggestion'])}</small>
                </div>
                """
            html_content += "</div>"
        
        # Add IDOR findings specifically
        if security_data['potential_ids']:
            html_content += """
            <h3 style="color: #6f42c1; margin-top: 30px;">🎯 Potential IDOR Parameters</h3>
            <div class="email-list">
            """
            for idor in security_data['potential_ids']:
                html_content += f"""
                <div class="email-item" style="border-left: 4px solid #6f42c1;">
                    <strong>Parameter: {html.escape(idor['parameter'])}</strong><br>
                    <small style="color: #666;">Value: {html.escape(idor['value'])}</small><br>
                    <small style="color: #007bff;">URL: <a href="{html.escape(idor['url'])}" target="_blank">{html.escape(idor['url'])}</a></small><br>
                    <small style="color: #666;">Context: {html.escape(idor['context'])}</small>
                </div>
                """
            html_content += "</div>"
        
        # Add recommendations
        if security_analysis['recommendations']:
            html_content += """
            <h3 style="color: #17a2b8; margin-top: 30px;">📝 Security Recommendations</h3>
            <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; border-left: 4px solid #17a2b8;">
            """
            for i, rec in enumerate(security_analysis['recommendations'][:10], 1):  # Limit to 10
                html_content += f"<p style='margin: 5px 0;'>{i}. {html.escape(rec)}</p>"
            html_content += "</div>"
        
        html_content += "</div>"  # Close security section
    
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
    except Exception:
        print(f"Error writing HTML file")
        return False

def generate_spider_html_report(spider_results, output_file, include_security=False):
    """Generate an HTML report for spider crawling results."""
    pages_data = spider_results['pages']
    summary = spider_results['summary']
    
    # Security: Check if file exists and warn user
    if os.path.exists(output_file):
        print(f"Warning: File {output_file} already exists and will be overwritten")
    
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
"""
    
    # Add security section if security analysis was performed
    if include_security and spider_results.get('security_analysis'):
        security_analysis = spider_results['security_analysis']
        
        html_content += f"""
        <div class="section">
            <h2 class="section-title">🔒 Security Analysis</h2>
            <div class="summary">
                <div class="summary-item">
                    <div class="summary-number">{security_analysis['summary']['risk_score']}</div>
                    <div class="summary-label">Risk Score</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number" style="color: #dc3545;">{len(security_analysis['high_risk_findings'])}</div>
                    <div class="summary-label">High Risk</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number" style="color: #fd7e14;">{len(security_analysis['medium_risk_findings'])}</div>
                    <div class="summary-label">Medium Risk</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number" style="color: #198754;">{len(security_analysis['low_risk_findings'])}</div>
                    <div class="summary-label">Low Risk</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number" style="color: #6f42c1;">{security_analysis['summary']['potential_idor_params']}</div>
                    <div class="summary-label">Potential IDORs</div>
                </div>
            </div>

        """
        
        # Add high risk findings
        if security_analysis['high_risk_findings']:
            html_content += """
            <h3 style="color: #dc3545; margin-top: 30px;">🚨 High Risk Findings</h3>
            <div class="email-list">
            """
            for finding in security_analysis['high_risk_findings']:
                html_content += f"""
                <div class="email-item" style="border-left: 4px solid #dc3545;">
                    <strong>{html.escape(finding['type'])}</strong><br>
                    <small style="color: #666;">{html.escape(finding['description'])}</small><br>
                    <small style="color: #007bff;">URL: <a href="{html.escape(finding['url'])}" target="_blank">{html.escape(finding['url'])}</a></small><br>
                    <small style="color: #28a745;">Test: {html.escape(finding['test_suggestion'])}</small>
                </div>
                """
            html_content += "</div>"
        
        # Add medium risk findings (limited to first 15 for spider report)
        if security_analysis['medium_risk_findings']:
            html_content += """
            <h3 style="color: #fd7e14; margin-top: 30px;">⚠️ Medium Risk Findings (Top 15)</h3>
            <div class="email-list">
            """
            for finding in security_analysis['medium_risk_findings'][:15]:
                html_content += f"""
                <div class="email-item" style="border-left: 4px solid #fd7e14;">
                    <strong>{html.escape(finding['type'])}</strong><br>
                    <small style="color: #666;">{html.escape(finding['description'])}</small><br>
                    <small style="color: #007bff;">URL: <a href="{html.escape(finding['url'])}" target="_blank">{html.escape(finding['url'])}</a></small><br>
                    <small style="color: #28a745;">Test: {html.escape(finding['test_suggestion'])}</small>
                </div>
                """
            html_content += "</div>"
        
        # Add recommendations
        if security_analysis['recommendations']:
            html_content += """
            <h3 style="color: #17a2b8; margin-top: 30px;">📝 Security Recommendations</h3>
            <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; border-left: 4px solid #17a2b8;">
            """
            for i, rec in enumerate(security_analysis['recommendations'][:12], 1):  # Limit to 12
                html_content += f"<p style='margin: 5px 0;'>{i}. {html.escape(rec)}</p>"
            html_content += "</div>"
        
        html_content += "</div>"  # Close security section
    
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
    except Exception:
        print(f"Error writing spider HTML file")
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
  
  # Security analysis
  python webscrape.py https://example.com --security  # Single page security scan
  python webscrape.py https://example.com --spider --security --depth 3  # Spider with security analysis
  python webscrape.py https://example.com --security -o security_report.html  # Save security findings
"""
    )
    
    parser.add_argument('url', nargs='?', help='URL to scrape (if not provided, will prompt for input)')
    parser.add_argument('-o', '--output', nargs='?', const='auto', 
                       help='Save results to HTML file. Use without filename to auto-generate.')
    
    # Spider-specific arguments
    parser.add_argument('--spider', action='store_true',
                       help='Enable spider mode to crawl multiple pages by following links')
    parser.add_argument('--depth', type=int, default=DEFAULT_SPIDER_DEPTH, 
                       help=f'Maximum crawl depth for spider mode (default: {DEFAULT_SPIDER_DEPTH}, max: {MAX_SPIDER_DEPTH_LIMIT})')
    parser.add_argument('--same-domain', action='store_true', default=True,
                       help='Only follow links on the same domain (default: True)')
    parser.add_argument('--all-domains', action='store_true',
                       help='Allow following links to external domains (overrides --same-domain)')
    parser.add_argument('--exclude', nargs='*', default=[],
                       help='Regex patterns to exclude from crawling (e.g., "blog" "admin")')
    parser.add_argument('--delay', type=float, default=DEFAULT_SPIDER_DELAY,
                       help=f'Delay between requests in seconds (default: {DEFAULT_SPIDER_DELAY})')
    
    # Security-specific arguments
    parser.add_argument('--security', action='store_true',
                       help='Enable security analysis mode to identify IDOR and injection vulnerabilities')
    
    return parser.parse_args()

def main() -> None:
    """Main entry point for the web scraping application.
    
    Handles command-line argument parsing, URL validation, and orchestrates
    either single-page scraping or spider crawling based on user options.
    Includes comprehensive error handling and optional HTML report generation.
    
    Raises:
        SystemExit: On validation errors, network failures, or user interruption
    """
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
            if args.security:
                print(f"🔒 Security analysis: ENABLED")
            
            # Set security mode flag for spider function
            if args.security:
                spider_website._security_mode = True
            
            # Run spider crawl
            spider_results = spider_website(
                start_url=url,
                max_depth=args.depth,
                same_domain_only=same_domain_only,
                exclude_patterns=args.exclude,
                delay=args.delay
            )
            
            # Perform security analysis if enabled
            if args.security:
                print(f"\n🔒 PERFORMING SECURITY ANALYSIS...")
                # Aggregate all security data from all pages
                all_security_data = {
                    'parameterized_urls': [],
                    'forms': [],
                    'input_fields': [],
                    'potential_ids': [],
                    'ajax_endpoints': []
                }
                
                for page_url, page_data in spider_results['pages'].items():
                    if page_data.get('security_data'):
                        for key in all_security_data.keys():
                            all_security_data[key].extend(page_data['security_data'].get(key, []))
                
                # Analyze security findings
                security_analysis = analyze_security_findings(all_security_data, url)
                spider_results['security_analysis'] = security_analysis
                
                # Print security summary
                print(f"\n🔒 SECURITY ANALYSIS RESULTS:")
                print(f"  📊 Risk Score: {security_analysis['summary']['risk_score']}")
                print(f"  🚨 High Risk Findings: {len(security_analysis['high_risk_findings'])}")
                print(f"  ⚠️  Medium Risk Findings: {len(security_analysis['medium_risk_findings'])}")
                print(f"  ℹ️  Low Risk Findings: {len(security_analysis['low_risk_findings'])}")
                print(f"  🎯 Potential IDOR Parameters: {security_analysis['summary']['potential_idor_params']}")
            
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
                
                if generate_spider_html_report(spider_results, output_file, args.security):
                    print(f"\u2705 Spider HTML report saved successfully to: {os.path.abspath(output_file)}")
                    print(f"Open the file in your browser to view the interactive results.")
                    if args.security:
                        print(f"\u2139️  Security findings included in report")
                else:
                    print("\u274c Failed to save spider HTML report.")
            
        else:
            # Single page mode: original functionality
            print(f"\n📄 SINGLE PAGE MODE")
            print(f"Fetching content from: {url}")
            
            # Add headers to appear more like a real browser
            headers = {
                'User-Agent': DEFAULT_USER_AGENT
            }
            
            response = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
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
            
            # Security analysis if enabled
            security_analysis = None
            if args.security:
                print("\n=== SECURITY ANALYSIS ===")
                security_data = extract_input_parameters(soup, url)
                security_analysis = analyze_security_findings(security_data, url)
                
                print(f"Security findings:")
                print(f"  🎯 Parameterized URLs: {len(security_data['parameterized_urls'])}")
                print(f"  📋 Forms found: {len(security_data['forms'])}")
                print(f"  📝 Input fields: {len(security_data['input_fields'])}")
                print(f"  🔍 Potential IDOR params: {len(security_data['potential_ids'])}")
                print(f"  🌐 AJAX endpoints: {len(security_data['ajax_endpoints'])}")
                print(f"  📊 Risk score: {security_analysis['summary']['risk_score']}")
                
                # Show high-risk findings
                if security_analysis['high_risk_findings']:
                    print(f"\n🚨 HIGH RISK FINDINGS:")
                    for i, finding in enumerate(security_analysis['high_risk_findings'], 1):
                        print(f"  {i}. {finding['type']}: {finding['description']}")
                        print(f"     URL: {finding['url']}")
                        print(f"     Test: {finding['test_suggestion']}")
                
                # Show medium-risk findings (limit to first 5)
                if security_analysis['medium_risk_findings']:
                    print(f"\n⚠️  MEDIUM RISK FINDINGS (showing first 5):")
                    for i, finding in enumerate(security_analysis['medium_risk_findings'][:5], 1):
                        print(f"  {i}. {finding['type']}: {finding['description']}")
                        print(f"     URL: {finding['url']}")
            
            # Summary
            print(f"\n=== SUMMARY ===")
            print(f"Total links found: {len(links)}")
            print(f"Total emails found: {len(emails)}")
            if args.security and security_analysis:
                print(f"Security risk score: {security_analysis['summary']['risk_score']}")
                print(f"High risk findings: {len(security_analysis['high_risk_findings'])}")
            
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
                
                # Create security data for HTML report if security mode was enabled
                html_security_data = None
                if args.security and security_analysis:
                    html_security_data = {
                        'security_data': security_data,
                        'security_analysis': security_analysis
                    }
                
                if generate_html_tree(url, links, emails, output_file, html_security_data):
                    print(f"\u2705 HTML report saved successfully to: {os.path.abspath(output_file)}")
                    print(f"Open the file in your browser to view the interactive results.")
                else:
                    print("\u274c Failed to save HTML report.")
        
    except requests.exceptions.RequestException as e:
        print(f"Error fetching the webpage: {type(e).__name__}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception:
        print(f"An unexpected error occurred")
        sys.exit(1)

if __name__ == "__main__":
    main()
