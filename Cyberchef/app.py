from flask import Flask, request, jsonify, send_from_directory
import base64
import hashlib
import urllib.parse
from flask_cors import CORS
import json
import html
import codecs
import csv
import io
import math
import re
from collections import Counter

app = Flask(__name__, static_folder='static')
CORS(app)  # Enable CORS for all routes

# Route to serve the main HTML page
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

# Route for the bake API endpoint
@app.route('/bake', methods=['POST'])
def bake():
    data = request.get_json()
    
    if not data or 'input' not in data or 'operations' not in data:
        return jsonify({'error': 'Invalid request format'}), 400
    
    input_data = data['input']
    operations = data['operations']
    
    result = input_data
    
    try:
        for operation in operations:
            result = process_operation(operation, result)
            
        return jsonify({'output': result})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

def process_operation(operation, data):
    """Process a single operation on the input data"""
    
    try:
        if operation == 'base64-encode':
            return base64.b64encode(data.encode('utf-8')).decode('utf-8')
        
        elif operation == 'base64-decode':
            return base64.b64decode(data.encode('utf-8')).decode('utf-8')
        
        elif operation == 'url-encode':
            return urllib.parse.quote_plus(data)
        
        elif operation == 'url-decode':
            return urllib.parse.unquote_plus(data)
        
        elif operation == 'hex-encode':
            return data.encode('utf-8').hex()
        
        elif operation == 'hex-decode':
            return bytes.fromhex(data).decode('utf-8')
        
        elif operation == 'reverse':
            return data[::-1]
        
        elif operation == 'to-uppercase':
            return data.upper()
        
        elif operation == 'to-lowercase':
            return data.lower()
        
        elif operation == 'md5':
            return hashlib.md5(data.encode('utf-8')).hexdigest()
        
        elif operation == 'sha1':
            return hashlib.sha1(data.encode('utf-8')).hexdigest()
        
        elif operation == 'sha256':
            return hashlib.sha256(data.encode('utf-8')).hexdigest()
        
        elif operation == 'rot13':
            return codecs.encode(data, 'rot_13')
        
        elif operation == 'binary-encode':
            return ' '.join(format(ord(c), '08b') for c in data)
        
        elif operation == 'binary-decode':
            return ''.join(chr(int(b, 2)) for b in data.split())
        
        elif operation == 'json-prettify':
            return json.dumps(json.loads(data), indent=2)
        
        elif operation == 'json-minify':
            return json.dumps(json.loads(data), separators=(',', ':'))
        
        elif operation == 'html-encode':
            return html.escape(data)
        
        elif operation == 'html-decode':
            return html.unescape(data)
        
        elif operation == 'csv-to-json':
            csv_data = csv.DictReader(io.StringIO(data))
            return json.dumps([row for row in csv_data], indent=2)
        
        elif operation == 'text-stats':
            chars = len(data)
            words = len(data.split())
            lines = len(data.splitlines()) or 1
            return json.dumps({
                'characters': chars,
                'words': words,
                'lines': lines
            }, indent=2)
        
        else:
            raise ValueError(f"Unknown operation: {operation}")
            
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON format")
    except csv.Error:
        raise ValueError("Invalid CSV format")
    except Exception as e:
        raise ValueError(f"Operation failed: {str(e)}")

def calculate_entropy(data):
    """Calculate Shannon entropy of a string"""
    if not data:
        return 0
    entropy = 0
    for x in Counter(data).values():
        p_x = x / len(data)
        entropy += -p_x * math.log2(p_x)
    return entropy

def is_base58(s):
    """Check if string is potentially base58 encoded"""
    return bool(re.match(r'^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$', s))

def from_base58(s):
    """Decode a Base58 string"""
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    decimal = 0
    for char in s:
        decimal = decimal * 58 + alphabet.index(char)
    return decimal.to_bytes((decimal.bit_length() + 7) // 8, byteorder='big')

@app.route('/operations', methods=['GET'])
def get_operations():
    """Return list of available operations"""
    operations = [
        {'id': 'base64-encode', 'name': 'Base64 Encode'},
        {'id': 'base64-decode', 'name': 'Base64 Decode'},
        {'id': 'url-encode', 'name': 'URL Encode'},
        {'id': 'url-decode', 'name': 'URL Decode'},
        {'id': 'hex-encode', 'name': 'Hex Encode'},
        {'id': 'hex-decode', 'name': 'Hex Decode'},
        {'id': 'reverse', 'name': 'Reverse'},
        {'id': 'to-uppercase', 'name': 'To Uppercase'},
        {'id': 'to-lowercase', 'name': 'To Lowercase'},
        {'id': 'md5', 'name': 'MD5 Hash'},
        {'id': 'sha1', 'name': 'SHA-1 Hash'},
        {'id': 'sha256', 'name': 'SHA-256 Hash'},
        {'id': 'rot13', 'name': 'ROT13 Cipher'},
        {'id': 'binary-encode', 'name': 'Binary Encode'},
        {'id': 'binary-decode', 'name': 'Binary Decode'},
        {'id': 'json-prettify', 'name': 'JSON Prettify'},
        {'id': 'json-minify', 'name': 'JSON Minify'},
        {'id': 'html-encode', 'name': 'HTML Encode'},
        {'id': 'html-decode', 'name': 'HTML Decode'},
        {'id': 'csv-to-json', 'name': 'CSV to JSON'},
        {'id': 'text-stats', 'name': 'Text Statistics'}
    ]
    return jsonify(operations)

# Add this route to help debug
@app.route('/test')
def test():
    return "Server is working!"

if __name__ == '__main__':
    print("Server starting at http://127.0.0.1:5006/")
    app.run(debug=True, port=5006)