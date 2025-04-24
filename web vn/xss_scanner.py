import requests
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from bs4 import BeautifulSoup
import re

class XssTester:
    def __init__(self):
        # Simple XSS payloads
        self.payloads = [
            '\\\"<script>alert(\"XSS\")</script>',
            '<script>alert(\"XSS\")</script>',
            '<ScRipT>alert(\"XSS\")</sCRipT>',
            '\\\'><script>alert(\"XSS\")</script>',
            '\\\"><script>alert(\"XSS\")</script>',
            '<img src=x onerror=alert(\"XSS\")>',
            'javascript:alert(\"XSS\")' # For href attributes
        ]
        # Pattern to check for unsanitized reflection (basic)
        # Looks for the core alert part without entity encoding
        self.reflection_pattern = re.compile(r'<script>alert\([\'\"]XSS[\'\"]\)</script>|onerror=alert\([\'\"]XSS[\'\"]\)', re.IGNORECASE)

    def test_url(self, url):
        results = {
            'vulnerable': False,
            'vulnerable_params': [],
            'details': []
        }
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        for param, values in query_params.items():
            original_value = values[0] # Test first value if multiple exist
            for payload in self.payloads:
                try:
                    # Create new query string with payload
                    test_params = query_params.copy()
                    test_params[param] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = parsed_url._replace(query=test_query).geturl()
                    
                    response = requests.get(test_url, timeout=5, verify=False, allow_redirects=True)
                    
                    # Check for reflection
                    if self.reflection_pattern.search(response.text):
                        results['vulnerable'] = True
                        results['vulnerable_params'].append(param)
                        results['details'].append({
                            'type': 'reflected_url',
                            'parameter': param,
                            'payload': payload
                        })
                        # Stop testing this param once a vulnerability is found
                        break 
                except requests.exceptions.RequestException as e:
                    # Log or handle request errors if needed
                    print(f"XSS URL test error for {param}: {e}") # Basic logging
                    pass # Continue testing other payloads/params
        return results

    def scan_forms(self, url):
        results = {
            'vulnerable_forms': [],
            'details': []
        }
        try:
            response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                form_details = self._test_form(url, form)
                if form_details:
                    results['vulnerable_forms'].append(form_details['action'])
                    results['details'].extend(form_details['details'])
        except requests.exceptions.RequestException as e:
            print(f"XSS form scan error accessing {url}: {e}")
        except Exception as e:
             print(f"XSS form scan general error: {e}")

        return results

    def _test_form(self, base_url, form):
        form_results = {
             'action': '',
             'vulnerable': False,
             'details': []
        }
        try:
            action = form.get('action', '')
            form_action_url = urljoin(base_url, action) if action else base_url
            method = form.get('method', 'get').lower()
            form_results['action'] = form_action_url

            inputs = form.find_all(['input', 'textarea', 'select'])
            form_data_template = {}
            testable_fields = []

            # Get default values and identify fields to test
            for input_tag in inputs:
                 name = input_tag.get('name')
                 input_type = input_tag.get('type', '').lower()
                 value = input_tag.get('value', '')

                 if name:
                     if input_type in ['text', 'search', 'email', 'url', 'tel'] or input_tag.name == 'textarea':
                         form_data_template[name] = 'TestValue' # Default test value
                         testable_fields.append(name)
                     elif input_type == 'hidden':
                          form_data_template[name] = value
                     elif input_type == 'password':
                          form_data_template[name] = 'TestPass123!'
                          testable_fields.append(name)
                     elif input_type in ['radio', 'checkbox'] and input_tag.has_attr('checked'):
                         form_data_template[name] = value
                     elif input_tag.name == 'select':
                         option = input_tag.find('option', selected=True)
                         form_data_template[name] = option['value'] if option and option.has_attr('value') else ''
                     # Add other input types if needed (submit buttons usually don't need values)


            # Test each vulnerable field with payloads
            for field_name in testable_fields:
                 for payload in self.payloads:
                    test_data = form_data_template.copy()
                    test_data[field_name] = payload
                    
                    try:
                        if method == 'post':
                            response = requests.post(form_action_url, data=test_data, timeout=5, verify=False, allow_redirects=True)
                        else: # GET
                            response = requests.get(form_action_url, params=test_data, timeout=5, verify=False, allow_redirects=True)

                        # Check for reflection
                        if self.reflection_pattern.search(response.text):
                            form_results['vulnerable'] = True
                            form_results['details'].append({
                                'type': 'reflected_form',
                                'form': form_action_url,
                                'field': field_name,
                                'payload': payload
                            })
                            # Optional: break testing this field once vuln found
                            # break 
                    except requests.exceptions.RequestException as e:
                         print(f"XSS Form test error for {field_name} in {form_action_url}: {e}")
                         pass # Continue

        except Exception as e:
             print(f"XSS _test_form general error: {e}")
        
        return form_results if form_results['vulnerable'] else None 