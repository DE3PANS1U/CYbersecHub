# CyberSecHub

A comprehensive cybersecurity toolkit that includes various security analysis and testing tools.

## Features

### Web Vulnerability Scanner
- Security Headers Analysis
- SSL/TLS Configuration Testing
- DNS Information Gathering
- WHOIS Information Lookup
- Common Vulnerability Detection
- CSRF Protection Analysis
- SQL Injection Testing
- Cross-Site Scripting (XSS) Detection
- File Discovery and Analysis
- PDF Report Generation

### Other Tools
- Hash Checker
- IP Address Analysis
- File Analysis
- URL Security Check
- OWASP Risk Calculator
- CyberChef-like Operations

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/CyberSecHub.git
cd CyberSecHub
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run the application:
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Usage

### Web Vulnerability Scanner

1. Navigate to the Web Scanner page
2. Enter the target URL
3. Select the desired scan options:
   - Security Headers
   - SSL/TLS Configuration
   - DNS Information
   - WHOIS Information
   - Common Vulnerabilities
   - CSRF Protection
   - SQL Injection
   - XSS (Cross-Site Scripting)
   - File Discovery
4. Click "Start Scan"
5. View the results in real-time
6. Export the results to PDF if needed

### Security Considerations

- The scanner is designed for security testing of systems you own or have permission to test
- Always obtain proper authorization before scanning any system
- Some tests may be intrusive and could trigger security controls
- Use responsibly and in accordance with applicable laws and regulations

## Dependencies

- Flask: Web framework
- Requests: HTTP library
- BeautifulSoup4: HTML parsing
- python-whois: WHOIS lookups
- dnspython: DNS queries
- python-nmap: Network scanning
- pyOpenSSL: SSL/TLS analysis
- reportlab: PDF generation
- pandas: Data manipulation
- html5lib: HTML parsing

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and testing purposes only. Users are responsible for obtaining proper authorization before scanning any systems. The authors are not responsible for any misuse or damage caused by this tool. 