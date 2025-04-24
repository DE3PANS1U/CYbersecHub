from flask import Flask, render_template, request, jsonify, make_response, send_from_directory
import requests
from bs4 import BeautifulSoup
import nmap
import urllib3
import ssl
import socket
import concurrent.futures
import dns.resolver
import whois
from datetime import datetime
import threading
import re
import subprocess
import json
from urllib.parse import urljoin, urlparse, unquote
import hashlib
import OpenSSL
import ssl
import warnings
import logging
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import time
import sys
from sql_injection import SQLInjectionTester
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET # Added for sitemap parsing
from xss_scanner import XssTester # Import the new XSS tester
from io import BytesIO
import html

# ReportLab Imports - Add back
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY, TA_RIGHT
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Disable SSL warnings
warnings.filterwarnings('ignore', category=InsecureRequestWarning)
urllib3.disable_warnings()

# Restore simple Flask app initialization
app = Flask(__name__, static_url_path='', static_folder='static')

# Global thread pool for reuse
thread_pool = ThreadPoolExecutor(max_workers=10)

# Cache for DNS and WHOIS lookups
dns_cache = {}
whois_cache = {}

def log_progress(message):
    """Log progress message with timestamp"""
    logger.info(message)
    return message

@lru_cache(maxsize=100)
def get_dns_info(hostname):
    """Get DNS information with caching and better timeout handling"""
    try:
        if hostname in dns_cache:
            return dns_cache[hostname]
            
        log_progress(f"Starting DNS scan for {hostname}")
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV']
        
        # Use multiple DNS servers
        dns_servers = [
            '8.8.8.8',      # Google DNS
            '1.1.1.1',      # Cloudflare DNS
            '208.67.222.222',  # OpenDNS
            '8.8.4.4'       # Google DNS secondary
        ]
        
        # Configure resolver with shorter timeouts and multiple servers
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2  # Reduce timeout to 2 seconds
        resolver.lifetime = 2  # Reduce lifetime to 2 seconds
        resolver.nameservers = dns_servers
        
        for record_type in record_types:
            try:
                log_progress(f"Checking {record_type} records...")
                answers = resolver.resolve(hostname, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                records[record_type] = []
            except dns.resolver.NXDOMAIN:
                records[record_type] = ['Domain does not exist']
            except dns.resolver.Timeout:
                records[record_type] = ['DNS query timed out']
            except dns.resolver.NoNameservers:
                records[record_type] = ['No DNS servers available']
            except Exception as e:
                records[record_type] = [f'Error: {str(e)}']
        
        # Try to get at least one successful record
        successful_records = sum(1 for rt in records.values() if rt and not any('Error:' in r for r in rt))
        
        if successful_records == 0:
            # If all queries failed, try one more time with a different DNS server
            log_progress("All DNS queries failed, trying with system DNS...")
            try:
                import socket
                system_dns = socket.gethostbyname(hostname)
                records['A'] = [system_dns]
                log_progress(f"Successfully resolved hostname using system DNS: {system_dns}")
            except Exception as e:
                log_progress(f"System DNS resolution also failed: {str(e)}")
        
        result = {
            'status': 'success' if successful_records > 0 else 'partial',
            'records': records,
            'total_records': sum(len(records[rt]) for rt in records),
            'successful_records': successful_records
        }
        
        # Cache the result
        dns_cache[hostname] = result
        return result
    except Exception as e:
        log_progress(f"Error in DNS scan: {str(e)}")
        return {'status': 'error', 'message': str(e)}

@lru_cache(maxsize=100)
def get_whois_info(hostname):
    """Get WHOIS information with caching"""
    try:
        if hostname in whois_cache:
            return whois_cache[hostname]
            
        w = whois.whois(hostname)
        
        # Clean and format dates
        def format_date(date):
            if isinstance(date, list):
                return [str(d) for d in date]
            return str(date) if date else None
        
        # Extract relevant information
        whois_data = {
            'registrar': w.registrar,
            'creation_date': format_date(w.creation_date),
            'expiration_date': format_date(w.expiration_date),
            'updated_date': format_date(w.updated_date),
            'name_servers': w.name_servers if isinstance(w.name_servers, list) else [w.name_servers] if w.name_servers else [],
            'status': w.status if isinstance(w.status, list) else [w.status] if w.status else [],
            'emails': w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else [],
            'dnssec': w.dnssec,
            'org': w.org,
            'country': w.country,
            'state': w.state,
            'city': w.city,
            'address': w.address,
            'zipcode': w.zipcode
        }
        
        result = {
            'status': 'success',
            'data': whois_data,
            'raw_text': w.text
        }
        
        # Cache the result
        whois_cache[hostname] = result
        return result
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

def scan_headers(url):
    """Scan HTTP headers"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        headers = dict(response.headers)
        
        # Define security headers and their recommended values
        security_headers = {
            'Strict-Transport-Security': {
                'value': headers.get('Strict-Transport-Security', 'Not Found'),
                'recommended': 'max-age=31536000; includeSubDomains',
                'description': 'Enforces HTTPS connections'
            },
            'X-Frame-Options': {
                'value': headers.get('X-Frame-Options', 'Not Found'),
                'recommended': 'DENY or SAMEORIGIN',
                'description': 'Prevents clickjacking attacks'
            },
            'X-Content-Type-Options': {
                'value': headers.get('X-Content-Type-Options', 'Not Found'),
                'recommended': 'nosniff',
                'description': 'Prevents MIME type sniffing'
            },
            'X-XSS-Protection': {
                'value': headers.get('X-XSS-Protection', 'Not Found'),
                'recommended': '1; mode=block',
                'description': 'Enables browser XSS filtering'
            },
            'Content-Security-Policy': {
                'value': headers.get('Content-Security-Policy', 'Not Found'),
                'recommended': "default-src 'self'",
                'description': 'Controls resource loading'
            },
            'Referrer-Policy': {
                'value': headers.get('Referrer-Policy', 'Not Found'),
                'recommended': 'strict-origin-when-cross-origin',
                'description': 'Controls referrer information'
            },
            'Permissions-Policy': {
                'value': headers.get('Permissions-Policy', 'Not Found'),
                'recommended': 'geolocation=(), microphone=(), camera=()',
                'description': 'Controls browser features'
            }
        }
        
        # Check for security issues
        security_issues = []
        
        # Check HSTS
        if 'Strict-Transport-Security' not in headers:
            security_issues.append({
                'header': 'Strict-Transport-Security',
                'issue': 'Missing HSTS header (SSL/TLS downgrade risk)',
                'severity': 'High'
            })
        
        # Check X-Frame-Options
        if 'X-Frame-Options' not in headers:
            security_issues.append({
                'header': 'X-Frame-Options',
                'issue': 'Missing X-Frame-Options header (Clickjacking risk)',
                'severity': 'High'
            })
        
        # Check X-Content-Type-Options
        if 'X-Content-Type-Options' not in headers:
            security_issues.append({
                'header': 'X-Content-Type-Options',
                'issue': 'Missing X-Content-Type-Options header (MIME-sniffing risk)',
                'severity': 'Medium'
            })
        
        # Check X-XSS-Protection
        if 'X-XSS-Protection' not in headers:
            security_issues.append({
                'header': 'X-XSS-Protection',
                'issue': 'Missing X-XSS-Protection header',
                'severity': 'Medium'
            })
        
        # Check Content-Security-Policy
        if 'Content-Security-Policy' not in headers:
            security_issues.append({
                'header': 'Content-Security-Policy',
                'issue': 'Missing Content-Security-Policy header',
                'severity': 'High'
            })
        
        # Check Referrer-Policy
        if 'Referrer-Policy' not in headers:
            security_issues.append({
                'header': 'Referrer-Policy',
                'issue': 'Missing Referrer-Policy header',
                'severity': 'Low'
            })
        
        # Check for server information disclosure
        if 'Server' in headers:
            security_issues.append({
                'header': 'Server',
                'issue': 'Server information disclosure',
                'severity': 'Low'
            })
        
        # Check for powered by information
        if 'X-Powered-By' in headers:
            security_issues.append({
                'header': 'X-Powered-By',
                'issue': 'Technology information disclosure',
                'severity': 'Low'
            })
        
        return {
            'status': 'success',
            'headers': security_headers,
            'security_issues': security_issues,
            'response_time': response.elapsed.total_seconds(),
            'status_code': response.status_code,
            'total_headers': len(headers),
            'security_headers_present': sum(1 for h in security_headers.values() if h['value'] != 'Not Found')
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Error scanning headers: {str(e)}',
            'headers': {},
            'security_issues': []
        }

def scan_ssl(url):
    """Optimized SSL scanning"""
    try:
        hostname = url.split('://')[1].split('/')[0]
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                
                # Get certificate details
                cert_info = {
                    'subject': dict(x[0] for x in cert['subject']),
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'version': cert['version'],
                    'serialNumber': cert['serialNumber'],
                    'notBefore': cert['notBefore'],
                    'notAfter': cert['notAfter'],
                    'subjectAltName': cert.get('subjectAltName', []),
                    'OCSP': cert.get('OCSP', []),
                    'caIssuers': cert.get('caIssuers', []),
                    'crlDistributionPoints': cert.get('crlDistributionPoints', [])
                }
                
                # Check for weak ciphers
                weak_ciphers = {
                    'RC4': 'RC4 is considered cryptographically broken',
                    'DES': 'DES is considered cryptographically broken',
                    '3DES': '3DES is considered weak',
                    'MD5': 'MD5 is considered cryptographically broken',
                    'SHA1': 'SHA1 is considered weak',
                    'NULL': 'NULL cipher provides no encryption',
                    'aNULL': 'aNULL cipher provides no authentication',
                    'EXPORT': 'EXPORT ciphers are intentionally weak',
                    'LOW': 'LOW strength ciphers are weak',
                    'MEDIUM': 'MEDIUM strength ciphers may be weak'
                }
                
                cipher_issues = []
                for weak, reason in weak_ciphers.items():
                    if weak in cipher[0]:
                        cipher_issues.append({
                            'cipher': cipher[0],
                            'issue': reason,
                            'severity': 'High'
                        })
                
                # Check certificate expiration
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (not_after - datetime.now()).days
                
                if days_until_expiry < 30:
                    cipher_issues.append({
                        'cipher': 'Certificate',
                        'issue': f'Certificate expires in {days_until_expiry} days',
                        'severity': 'High'
                    })
                
                # Check for wildcard certificates
                if any('*.' in san[1] for san in cert.get('subjectAltName', [])):
                    cipher_issues.append({
                        'cipher': 'Certificate',
                        'issue': 'Wildcard certificate in use',
                        'severity': 'Medium'
                    })
                
                return {
                    'status': 'success',
                    'certificate': cert_info,
                    'cipher_suite': {
                        'name': cipher[0],
                        'version': cipher[1],
                        'bits': cipher[2]
                    },
                    'cipher_issues': cipher_issues,
                    'days_until_expiry': days_until_expiry,
                    'protocol_version': ssock.version(),
                    'total_issues': len(cipher_issues)
                }
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

def check_common_vulnerabilities(url):
    """Check for common vulnerabilities (excluding CSRF)"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        vulnerabilities = []
        
        # Check for forms issues
        forms = soup.find_all('form')
        for form in forms:
            # Check for sensitive fields
            if form.find('input', {'type': 'password'}) and not form.get('action', '').startswith('https://'):
                vulnerabilities.append({
                    'type': 'Form Security',
                    'severity': 'High',
                    'description': 'Password form submitting over insecure HTTP',
                    'element': str(form)[:200] + '...'
                })
        
        # Check for password inputs without autocomplete=off
        password_inputs = soup.find_all('input', {'type': 'password'})
        for pwd in password_inputs:
            if not pwd.get('autocomplete') == 'off':
                vulnerabilities.append({
                    'type': 'Form Security',
                    'severity': 'Medium',
                    'description': 'Password input found without autocomplete=off',
                    'element': str(pwd)
                })
        
        # Check for mixed content
        if url.startswith('https://'):
            for tag in soup.find_all(['script', 'link', 'img']):
                src = tag.get('src') or tag.get('href')
                if src and src.startswith('http://'):
                    vulnerabilities.append({
                        'type': 'Mixed Content',
                        'severity': 'Medium',
                        'description': f'Mixed content: Loading resource over HTTP on HTTPS page: {src}',
                        'element': str(tag)
                    })
        
        # Check for missing security headers in forms
        for form in forms:
            if not form.get('autocomplete'):
                vulnerabilities.append({
                    'type': 'Form Security',
                    'severity': 'Low',
                    'description': 'Form missing autocomplete attribute',
                    'element': str(form)[:200] + '...'
                })
            if not form.get('novalidate'):
                vulnerabilities.append({
                    'type': 'Form Security',
                    'severity': 'Low',
                    'description': 'Form missing novalidate attribute',
                    'element': str(form)[:200] + '...'
                })
        
        # Check for SQL injection vulnerable forms
        for form in forms:
            action = form.get('action', '')
            if any(keyword in action.lower() for keyword in ['search', 'query', 'id', 'item']):
                vulnerabilities.append({
                    'type': 'SQL Injection',
                    'severity': 'Medium',
                    'description': 'Form may be vulnerable to SQL injection',
                    'element': str(form)[:200] + '...'
                })
        
        # Check for XSS vulnerable inputs
        for input_tag in soup.find_all('input'):
            if not input_tag.get('type') in ['hidden', 'submit', 'button']:
                vulnerabilities.append({
                    'type': 'XSS',
                    'severity': 'Medium',
                    'description': 'Input field may be vulnerable to XSS',
                    'element': str(input_tag)
                })
        
        return {
            'status': 'success',
            'vulnerabilities': vulnerabilities,
            'forms_analyzed': len(forms),
            'password_fields': len(password_inputs),
            'total_checks': 7
        }
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

def check_sql_injection(url):
    """Check for SQL injection vulnerabilities"""
    try:
        sql_tester = SQLInjectionTester()
        
        # Test URL parameters
        url_results = sql_tester.test_url(url)
        
        # Test forms
        form_results = sql_tester.scan_form(url)
        
        return {
            'status': 'success',
            'url_vulnerable': url_results['vulnerable'],
            'url_vulnerable_params': url_results['vulnerable_params'],
            'form_vulnerable': len(form_results['vulnerable_forms']) > 0,
            'vulnerable_forms': form_results['vulnerable_forms'],
            'details': url_results['details'] + form_results['details']
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
        }

# --- New Function: CSRF Check ---
def check_csrf(url):
    """Check forms for missing CSRF tokens."""
    vulnerabilities = []
    common_csrf_names = ['csrf_token', 'authenticity_token', '_csrf', '_token', 'csrfmiddlewaretoken', 'xsrf_token']
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            is_post_form = form.get('method', 'get').lower() == 'post'
            has_csrf_token = False
            hidden_inputs = form.find_all('input', {'type': 'hidden'})
            for hidden_input in hidden_inputs:
                name = hidden_input.get('name', '').lower()
                if any(csrf_name in name for csrf_name in common_csrf_names):
                    has_csrf_token = True
                    break
            
            if is_post_form and not has_csrf_token:
                vulnerabilities.append({
                    'type': 'CSRF Protection', 
                    'severity': 'Medium',
                    'description': 'POST form may be missing CSRF token protection.',
                    'element': str(form)[:200] + '...'
                })
        
        return {
            'status': 'success',
            'vulnerabilities': vulnerabilities
        }
    except Exception as e:
        logger.error(f"Error during CSRF check for {url}: {e}")
        return {
            'status': 'error',
            'message': str(e),
            'vulnerabilities': []
        }
# --- End New Function ---

# --- New Function: Analyze robots.txt and sitemap.xml ---

def analyze_discovery_files(base_url):
    results = {
        'robots': {'status': 'not_found', 'disallowed': [], 'allowed': [], 'sitemaps': [], 'raw': None, 'error': None},
        'sitemap': {'status': 'not_found', 'urls': [], 'error': None}
    }
    robots_url = urljoin(base_url, '/robots.txt')
    sitemap_urls_to_check = set()

    # 1. Fetch and parse robots.txt
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(robots_url, headers=headers, timeout=5, verify=False)
        if response.status_code == 200:
            results['robots']['status'] = 'found'
            results['robots']['raw'] = response.text
            current_ua = None
            for line in response.text.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key, value = parts[0].strip().lower(), parts[1].strip()
                    if key == 'user-agent':
                        current_ua = value
                    elif key == 'disallow' and current_ua in ('*', headers['User-Agent']): # Check rules for * or our UA
                        results['robots']['disallowed'].append(value)
                    elif key == 'allow' and current_ua in ('*', headers['User-Agent']):
                         results['robots']['allowed'].append(value)
                    elif key == 'sitemap':
                        results['robots']['sitemaps'].append(value)
                        sitemap_urls_to_check.add(value)
        else:
            results['robots']['status'] = 'not_found'
    except Exception as e:
        results['robots']['status'] = 'error'
        results['robots']['error'] = str(e)

    # If robots.txt didn't specify sitemaps, check common location
    if not sitemap_urls_to_check:
         sitemap_urls_to_check.add(urljoin(base_url, '/sitemap.xml'))

    # 2. Fetch and parse sitemap.xml (or others specified)
    all_sitemap_urls = set()
    for sitemap_url in sitemap_urls_to_check:
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(sitemap_url, headers=headers, timeout=10, verify=False)
            if response.status_code == 200:
                results['sitemap']['status'] = 'found'
                try:
                    root = ET.fromstring(response.content)
                    # Find URLs within the sitemap (common namespaces)
                    namespaces = {
                        'sm': 'http://www.sitemaps.org/schemas/sitemap/0.9',
                        'image': 'http://www.google.com/schemas/sitemap-image/1.1', # Example, add more if needed
                     }
                    # Look for <url>/<loc> or <sitemap>/<loc>
                    url_elements = root.findall('.//sm:url/sm:loc', namespaces) + root.findall('.//sm:sitemap/sm:loc', namespaces)
                    for loc in url_elements:
                        if loc.text:
                             all_sitemap_urls.add(loc.text.strip())
                    # If it's a sitemap index, we might need to parse nested sitemaps (simplified here)
                except ET.ParseError as pe:
                    results['sitemap']['status'] = 'parse_error'
                    results['sitemap']['error'] = f'XML Parse Error: {str(pe)}'
                except Exception as parse_e:
                    results['sitemap']['status'] = 'parse_error'
                    results['sitemap']['error'] = f'Error parsing sitemap: {str(parse_e)}'
            # Keep 'not_found' if initial check failed and no sitemaps were found later
            elif results['sitemap']['status'] == 'not_found': 
                results['sitemap']['status'] = 'not_found'
        except Exception as e:
            # Only report error if we haven't already found one
            if results['sitemap']['status'] != 'parse_error':
                results['sitemap']['status'] = 'error'
                results['sitemap']['error'] = str(e)

    results['sitemap']['urls'] = sorted(list(all_sitemap_urls))
    return results
# --- End New Function ---

# --- New Function: XSS Scan ---
def check_xss(url):
    """Check for reflected XSS vulnerabilities"""
    try:
        xss_tester = XssTester()
        url_results = xss_tester.test_url(url)
        form_results = xss_tester.scan_forms(url)
        
        # Combine results
        vulnerable = url_results['vulnerable'] or len(form_results['vulnerable_forms']) > 0
        details = url_results['details'] + form_results['details']
        vulnerable_params = url_results['vulnerable_params']
        vulnerable_forms = form_results['vulnerable_forms']

        return {
            'status': 'success',
            'vulnerable': vulnerable,
            'vulnerable_params': vulnerable_params,
            'vulnerable_forms': vulnerable_forms,
            'details': details
        }
    except Exception as e:
        logger.error(f"Error during XSS check for {url}: {e}")
        return {
            'status': 'error',
            'message': str(e),
            'vulnerable': False,
            'vulnerable_params': [],
            'vulnerable_forms': [],
            'details': []
        }
# --- End New Function ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        url = data.get('url')
        categories = data.get('categories') 
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        if not categories or not isinstance(categories, list) or len(categories) == 0:
            return jsonify({'error': 'At least one scan category must be selected'}), 400

        scan_functions = {
            'headers': scan_headers,
            'ssl': scan_ssl,
            'dns': get_dns_info,
            'whois': get_whois_info,
            'vuln': check_common_vulnerabilities,
            'csrf': check_csrf, 
            'sql': check_sql_injection,
            'xss': check_xss,
            'discovery': analyze_discovery_files
        }
        result_keys = {
            'headers': 'header_scan',
            'ssl': 'ssl_scan',
            'dns': 'dns_info',
            'whois': 'whois_info',
            'vuln': 'vulnerability_scan',
            'csrf': 'csrf_scan',
            'sql': 'sql_injection_scan',
            'xss': 'xss_scan',
            'discovery': 'discovery_scan'
        }

        hostname = None
        try:
            if any(cat in categories for cat in ['dns', 'whois', 'ssl']):
                 parsed_url = urlparse(url)
                 hostname = parsed_url.netloc or parsed_url.path.split('/')[0]
                 if not hostname: 
                     raise ValueError("Could not parse hostname")
                 # Ensure hostname is a string
                 hostname = str(hostname)
        except Exception as e:
              return jsonify({'error': f'Invalid URL or could not extract hostname: {e}'}), 400

        futures = {}
        scan_results = {}
        
        # Run selected scans in parallel and wait for completion
        with ThreadPoolExecutor(max_workers=5) as executor:
            for category in categories:
                if category in scan_functions:
                    func = scan_functions[category]
                    arg = url
                    if category in ['dns', 'whois']:
                        arg = hostname
                    elif category == 'ssl': 
                         arg = url 
                    futures[category] = executor.submit(func, arg)
            
            # Get results as they complete
            for category, future in futures.items():
                result_key = result_keys.get(category)
                if result_key:
                    try:
                        scan_results[result_key] = future.result()
                    except Exception as e:
                        logger.error(f"Error getting result for {category} ({result_key}): {e}")
                        # Store error in the result for the frontend to display
                        scan_results[result_key] = {'status': 'error', 'message': f'Scan execution failed: {str(e)}'}
        
        # Add fixed info
        scan_results['target_url'] = url
        scan_results['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        scan_results['scans_performed'] = [result_keys[cat] for cat in categories if cat in result_keys] 

        return jsonify(scan_results), 200 # Return 200 OK with full results
        
    except Exception as e:
        logger.error(f"General scan error: {e}", exc_info=True)
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

@app.route('/test')
def test_page():
    return render_template('test.html')

@app.route('/submit', methods=['POST'])
def submit_form():
    name = request.form.get('name')
    email = request.form.get('email')
    return jsonify({'status': 'success', 'message': f'Form submitted with name: {name}, email: {email}'})

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    return jsonify({'status': 'success', 'message': 'Login attempt processed'})

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q')
    return jsonify({'status': 'success', 'message': f'Search query: {query}'})

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file provided'})
    file = request.files['file']
    return jsonify({'status': 'success', 'message': f'File {file.filename} uploaded'})

@app.route('/comment', methods=['POST'])
def comment():
    comment_text = request.form.get('comment')
    return jsonify({'status': 'success', 'message': f'Comment received: {comment_text}'})

@app.route('/process', methods=['POST'])
def process():
    user_id = request.form.get('user_id')
    token = request.form.get('token')
    message = request.form.get('message')
    return jsonify({'status': 'success', 'message': 'Form processed successfully'})

@app.route('/item')
def item():
    item_id = request.args.get('id')
    item_type = request.args.get('type')
    return jsonify({'status': 'success', 'message': f'Item {item_id} of type {item_type}'})

@app.route('/user')
def user():
    name = request.args.get('name')
    role = request.args.get('role')
    return jsonify({'status': 'success', 'message': f'User {name} with role {role}'})

# --- PDF Export Route (Using ReportLab) --- ADD BACK
@app.route('/export_pdf', methods=['POST'])
def export_pdf():
    try:
        scan_data = request.get_json()
        if not scan_data:
            return jsonify({"error": "Missing scan data"}), 400

        pdf_buffer = BytesIO()
        doc = SimpleDocTemplate(pdf_buffer, pagesize=A4,
                                leftMargin=1.5*cm, rightMargin=1.5*cm,
                                topMargin=1.5*cm, bottomMargin=1.5*cm)
        styles = getSampleStyleSheet()
        escape = html.escape # Shortcut for escaping

        # --- Define Custom Styles ---
        styles.add(ParagraphStyle(name='ReportTitle', parent=styles['h1'], alignment=TA_CENTER, fontSize=24, spaceAfter=1*cm, textColor=colors.darkblue))
        styles.add(ParagraphStyle(name='SectionTitle', parent=styles['h2'], fontSize=16, spaceBefore=0.8*cm, spaceAfter=0.3*cm, textColor=colors.darkslategray))
        styles.add(ParagraphStyle(name='SubTitle', parent=styles['h3'], fontSize=12, spaceBefore=0.5*cm, spaceAfter=0.2*cm, textColor=colors.darkslategray))
        styles.add(ParagraphStyle(name='NormalRight', parent=styles['Normal'], alignment=TA_RIGHT))
        
        # Modify the existing 'Code' style
        code_style = styles['Code']
        code_style.wordWrap = 'CJK'
        code_style.fontSize = 9
        code_style.leading = 11
        code_style.backColor = colors.whitesmoke
        code_style.borderColor = colors.lightgrey
        code_style.borderWidth = 1
        code_style.borderPadding = (5,5,5,5) # Tuple for padding
        
        # Add custom Issue styles (these names are unique)
        styles.add(ParagraphStyle(name='IssueHigh', parent=styles['Normal'], backColor=colors.lightpink, borderColor=colors.red, borderPadding=(5,5,5,5), spaceAfter=3, leading=12))
        styles.add(ParagraphStyle(name='IssueMedium', parent=styles['Normal'], backColor=colors.lightyellow, borderColor=colors.orange, borderPadding=(5,5,5,5), spaceAfter=3, leading=12))
        styles.add(ParagraphStyle(name='IssueLow', parent=styles['Normal'], backColor=colors.lightblue, borderColor=colors.blue, borderPadding=(5,5,5,5), spaceAfter=3, leading=12))
        
        # Add custom Text styles (these names are unique)
        styles.add(ParagraphStyle(name='SuccessText', parent=styles['Normal'], textColor=colors.darkgreen))
        styles.add(ParagraphStyle(name='ErrorText', parent=styles['Normal'], textColor=colors.red))
        styles.add(ParagraphStyle(name='WarningText', parent=styles['Normal'], textColor=colors.darkorange))

        # --- Build Story (List of Flowables) ---
        story = []
        story.append(Paragraph("Web Vulnerability Scan Report", styles['ReportTitle']))

        # Scan Overview
        story.append(Paragraph("Scan Overview", styles['SectionTitle']))
        story.append(Paragraph(f"<b>Target URL:</b> {escape(scan_data.get('target_url', 'N/A'))}", styles['Normal']))
        story.append(Paragraph(f"<b>Scan Timestamp:</b> {escape(scan_data.get('timestamp', 'N/A'))}", styles['Normal']))
        story.append(Paragraph(f"<b>Scans Performed:</b> {escape(', '.join(scan_data.get('scans_performed', [])))}", styles['Normal']))
        story.append(Spacer(1, 0.5*cm))

        # Helper to add sections
        def add_section(title, data, render_func):
            if data:
                story.append(Paragraph(escape(title), styles['SectionTitle']))
                if data.get('status') == 'success':
                    try:
                        render_func(data)
                    except Exception as render_e:
                        logger.error(f"Error rendering PDF section '{title}': {render_e}", exc_info=True)
                        story.append(Paragraph(f"Error rendering section: {escape(str(render_e))}", styles['ErrorText']))
                else:
                    story.append(Paragraph(f"Scan failed: {escape(data.get('message', 'Unknown error'))}", styles['ErrorText']))
                story.append(Spacer(1, 0.5*cm))

        # Render Functions per Section (Ensure these are correctly defined as nested functions or methods)
        def render_headers(data):
            # ... (Implementation from previous accepted version) ...
            if 'headers' in data:
                for header, info in data['headers'].items():
                    val = info.get('value', 'Not Found')
                    status = "Found" if val != 'Not Found' else "Missing"
                    rec = info.get('recommended', 'N/A')
                    desc = info.get('description', 'N/A')
                    val_display = escape(val) if status == 'Found' else val 
                    story.append(Paragraph(f"<b>{escape(header)}:</b> {status} ({val_display})", styles['Normal']))
                    story.append(Paragraph(f"<font size=8><i>Recommended: {escape(rec)}<br/>Description: {escape(desc)}</i></font>", styles['Normal']))
                    story.append(Spacer(1, 0.1*cm))
            if data.get('security_issues'):
                story.append(Paragraph("Header Security Issues:", styles['SubTitle']))
                for issue in data['security_issues']:
                    sev = issue.get('severity', 'low').lower()
                    style_name = {'high': 'IssueHigh', 'medium': 'IssueMedium', 'low': 'IssueLow'}.get(sev, 'IssueLow')
                    story.append(Paragraph(f"<b>{escape(issue.get('header', ''))}:</b> {escape(issue.get('issue', ''))} <b>({escape(issue.get('severity', ''))})</b>", styles[style_name]))
            else:
                 story.append(Paragraph("No explicit header security issues found.", styles['SuccessText']))

        def render_ssl(data):
            # ... (Implementation from previous accepted version) ...
            story.append(Paragraph(f"<b>Protocol Version:</b> {escape(data.get('protocol_version', 'N/A'))}", styles['Normal']))
            story.append(Paragraph(f"<b>Days Until Expiry:</b> {escape(str(data.get('days_until_expiry', 'N/A')))}", styles['Normal']))
            cipher = data.get('cipher_suite')
            cipher_text = f"{escape(cipher.get('name', ''))} ({escape(str(cipher.get('bits', '')))} bits)" if cipher else 'N/A'
            story.append(Paragraph(f"<b>Cipher Suite:</b> {cipher_text}", styles['Normal']))
            if data.get('cipher_issues'):
                story.append(Paragraph("Cipher Issues:", styles['SubTitle']))
                for issue in data['cipher_issues']:
                    sev = issue.get('severity', 'low').lower()
                    style_name = {'high': 'IssueHigh', 'medium': 'IssueMedium', 'low': 'IssueLow'}.get(sev, 'IssueLow')
                    story.append(Paragraph(f"{escape(issue.get('issue', ''))} (Cipher: {escape(issue.get('cipher', ''))}) <b>({escape(issue.get('severity', ''))})</b>", styles[style_name]))
            else:
                 story.append(Paragraph("No significant cipher issues found.", styles['SuccessText']))

        def render_dns(data):
            # ... (Implementation from previous accepted version) ...
            found = False
            errors = []
            for type, records in data.get('records', {}).items():
                if records:
                    record_str = str(records[0]) 
                    if not record_str.startswith('Error:'):
                        found = True
                        story.append(Paragraph(f"{escape(type)} Records:", styles['SubTitle']))
                        for record in records:
                             story.append(Paragraph(escape(str(record)), styles['Code']))
                        story.append(Spacer(1, 0.1*cm))
                    else:
                        errors.append((type, record_str))
            if not found:
                story.append(Paragraph("No standard DNS records found.", styles['Normal']))
            if errors:
                 story.append(Paragraph(f"DNS Lookup Errors:", styles['SubTitle']))
                 for type, err_msg in errors:
                     story.append(Paragraph(f"<b>{escape(type)}:</b> {escape(err_msg)}", styles['WarningText']))

        def render_whois(data):
            # ... (Implementation from previous accepted version) ...
            w_data = data.get('data', {})
            fields = ['registrar', 'creation_date', 'expiration_date', 'updated_date', 'name_servers', 'status', 'org', 'country']
            for field in fields:
                val = w_data.get(field)
                if isinstance(val, list):
                     val = ', '.join(map(str, val))
                else:
                     val = str(val) if val is not None else 'N/A'
                story.append(Paragraph(f"<b>{escape(field.replace('_', ' ').title())}:</b> {escape(val)}", styles['Normal']))
            raw = data.get('raw_text')
            if raw:
                story.append(Paragraph("Raw WHOIS Data:", styles['SubTitle']))
                story.append(Paragraph(escape(raw), styles['Code']))

        def render_vuln(data):
            # ... (Implementation from previous accepted version) ...
            if data.get('vulnerabilities'):
                 for vuln in data['vulnerabilities']:
                    sev = vuln.get('severity', 'low').lower()
                    style_name = {'high': 'IssueHigh', 'medium': 'IssueMedium', 'low': 'IssueLow'}.get(sev, 'IssueLow')
                    el = f"<br/>Element: <br/><code>{escape(vuln.get('element', ''))[:200]}...</code>" if vuln.get('element') else ""
                    story.append(Paragraph(f"<b>{escape(vuln.get('type', ''))}:</b> {escape(vuln.get('description', ''))} <b>({escape(vuln.get('severity', ''))})</b>{el}", styles[style_name]))
            else:
                story.append(Paragraph("No common page vulnerabilities found (excluding CSRF).", styles['SuccessText']))

        def render_csrf(data):
             # ... (Implementation from previous accepted version) ...
             if data.get('vulnerabilities'):
                 for vuln in data['vulnerabilities']:
                    sev = vuln.get('severity', 'low').lower()
                    style_name = {'high': 'IssueHigh', 'medium': 'IssueMedium', 'low': 'IssueLow'}.get(sev, 'IssueLow')
                    el = f"<br/>Form Element:<br/><code>{escape(vuln.get('element', ''))[:200]}...</code>" if vuln.get('element') else ""
                    story.append(Paragraph(f"<b>{escape(vuln.get('type', ''))}:</b> {escape(vuln.get('description', ''))} <b>({escape(vuln.get('severity', ''))})</b>{el}", styles[style_name]))
             else:
                 story.append(Paragraph("No POST forms found missing potential CSRF tokens.", styles['SuccessText']))

        def render_sqli(data):
             # ... (Implementation from previous accepted version) ...
             is_vuln = data.get('url_vulnerable') or data.get('form_vulnerable')
             status_text = "Potentially Vulnerable" if is_vuln else "Seems Safe"
             status_style = styles['ErrorText'] if is_vuln else styles['SuccessText']
             story.append(Paragraph(f"<b>Overall Status:</b> {status_text}", status_style))
             story.append(Paragraph(f"<font size=9>URL Parameters Vulnerable: {'Yes' if data.get('url_vulnerable') else 'No'}<br/>"+
                                    f"Forms Vulnerable: {'Yes' if data.get('form_vulnerable') else 'No'}</font>", styles['Normal']))
             if data.get('details'):
                story.append(Paragraph("Detection Details:", styles['SubTitle']))
                for detail in data['details']:
                    loc = f"Param: <code>{escape(str(detail.get('parameter', '')))}</code>" if detail.get('parameter') else ''
                    loc += f" Form: <code>{escape(str(detail.get('form', '')))}</code> Field: <code>{escape(str(detail.get('field', '')))}</code>" if detail.get('form') else ''
                    story.append(Paragraph(f"<b>Type:</b> {escape(detail.get('type', ''))} | {loc}<br/>"+
                                         f"Payload Used: <code>{escape(detail.get('payload', ''))}</code>", styles['IssueMedium']))

        def render_xss(data):
            # ... (Implementation from previous accepted version) ...
            is_vuln = data.get('vulnerable')
            status_text = "Potentially Vulnerable" if is_vuln else "Seems Safe"
            status_style = styles['ErrorText'] if is_vuln else styles['SuccessText']
            story.append(Paragraph(f"<b>Overall Status:</b> {status_text}", status_style))
            url_vuln = data.get('vulnerable_params') and len(data['vulnerable_params']) > 0
            form_vuln = data.get('vulnerable_forms') and len(data['vulnerable_forms']) > 0
            story.append(Paragraph(f"<font size=9>URL Parameters Vulnerable: {'Yes' if url_vuln else 'No'}<br/>"+
                                    f"Forms Vulnerable: {'Yes' if form_vuln else 'No'}</font>", styles['Normal']))
            if data.get('details'):
                story.append(Paragraph("Detection Details:", styles['SubTitle']))
                for detail in data['details']:
                    loc = f"Param: <code>{escape(str(detail.get('parameter', '')))}</code>" if detail.get('parameter') else ''
                    loc += f" Form: <code>{escape(str(detail.get('form', '')))}</code> Field: <code>{escape(str(detail.get('field', '')))}</code>" if detail.get('form') else ''
                    story.append(Paragraph(f"<b>Type:</b> {escape(detail.get('type', ''))} | {loc}<br/>"+
                                         f"Payload Used: <code>{escape(detail.get('payload', ''))}</code>", styles['IssueMedium']))

        def render_discovery(data):
            # ... (Implementation from previous accepted version) ...
            story.append(Paragraph("robots.txt", styles['SubTitle']))
            robots_data = data.get('robots', {})
            if robots_data.get('status') == 'found':
                story.append(Paragraph("Status: Found", styles['SuccessText']))
                if robots_data.get('disallowed'): story.append(Paragraph(f"Disallowed: {escape(', '.join(robots_data['disallowed']))}", styles['Normal']))
                if robots_data.get('sitemaps'): story.append(Paragraph(f"Sitemaps: {escape(', '.join(robots_data['sitemaps']))}", styles['Normal']))
                if robots_data.get('raw'): 
                    story.append(Paragraph(f"Raw Content:", styles['Normal']))
                    story.append(Paragraph(escape(robots_data['raw']), styles['Code'])) 
            elif robots_data.get('status') == 'not_found':
                 story.append(Paragraph("Status: Not Found", styles['Normal']))
            else:
                 story.append(Paragraph(f"Status: Error ({escape(robots_data.get('error', ''))})", styles['ErrorText']))
            story.append(Spacer(1, 0.2*cm))
            story.append(Paragraph("sitemap.xml", styles['SubTitle']))
            sitemap_data = data.get('sitemap', {})
            if sitemap_data.get('status') == 'found':
                story.append(Paragraph("Status: Found & Parsed", styles['SuccessText']))
                if sitemap_data.get('urls'):
                    story.append(Paragraph(f"URLs Found ({len(sitemap_data['urls'])}):", styles['Normal']))
                    display_urls = sitemap_data['urls'][:20] # Show first 20
                    for u in display_urls:
                         story.append(Paragraph(escape(u), styles['Code']))
                    if len(sitemap_data['urls']) > 20:
                         story.append(Paragraph(f"<i>... and {len(sitemap_data['urls']) - 20} more</i>", styles['Normal']))
                else:
                    story.append(Paragraph("No URLs found in sitemap.", styles['Normal']))
            elif sitemap_data.get('status') == 'not_found':
                 story.append(Paragraph("Status: Not Found", styles['Normal']))
            elif sitemap_data.get('status') == 'parse_error':
                story.append(Paragraph(f"Status: Parse Error ({escape(sitemap_data.get('error', ''))})", styles['ErrorText']))
            else:
                 story.append(Paragraph(f"Status: Fetch Error ({escape(sitemap_data.get('error', ''))})", styles['ErrorText']))

        # Add sections based on scan data present in the JSON
        scan_render_map = {
            'header_scan': ("Security Headers", render_headers),
            'ssl_scan': ("SSL/TLS Information", render_ssl),
            'dns_info': ("DNS Information", render_dns),
            'whois_info': ("WHOIS Information", render_whois),
            'vulnerability_scan': ("Page Analysis", render_vuln),
            'csrf_scan': ("CSRF Protection Analysis", render_csrf),
            'sql_injection_scan': ("SQL Injection Analysis", render_sqli),
            'xss_scan': ("Cross-Site Scripting (XSS) Analysis", render_xss),
            'discovery_scan': ("Discovery Files", render_discovery)
        }
        
        for scan_key, (title, render_func) in scan_render_map.items():
            if scan_key in scan_data:
                 add_section(title, scan_data.get(scan_key), render_func)
        
        # Build the PDF
        doc.build(story)

        pdf_bytes = pdf_buffer.getvalue()
        pdf_buffer.close()

        # Create filename
        target_host = urlparse(scan_data.get('target_url', '')).hostname or 'scan'
        timestamp_str = scan_data.get('timestamp', '').replace(':', '-').replace(' ', '_')
        filename = f"{target_host}_{timestamp_str}_report.pdf"

        # Create response
        response = make_response(pdf_bytes)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response

    except Exception as e:
        logger.error(f"PDF Export Error (ReportLab): {e}", exc_info=True)
        return jsonify({"error": f"Failed to generate PDF report using ReportLab: {str(e)}"}), 500
# --- End PDF Export Route (ReportLab) ---

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)

if __name__ == '__main__':
    app.run(debug=True, port=5000) 