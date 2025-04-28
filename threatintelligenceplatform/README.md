# Threat Intelligence Platform Web Dashboard

This project is a modern web dashboard that queries the [Threat Intelligence Platform API](https://threatintelligenceplatform.com/) for a given domain and displays the results in a user-friendly, visually organized format.

## Features
- Input a domain name and view:
  - Infrastructure analysis
  - SSL certificate chain
  - SSL configuration
  - Malware check
  - Connected domains
  - Reputation (v1 & v2)
- Modern, responsive UI (HTML, CSS, JS)
- Recommendations and warnings highlighted

## Setup
1. **Clone the repository**
2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```
3. **Set your Threat Intelligence Platform API key**
   - Edit `app.py` and set `API_KEY` to your key (or use an environment variable for security).
4. **Run the app**
   ```bash
   python app.py
   ```
5. **Open in browser**
   - Visit [http://127.0.0.1:5000](http://127.0.0.1:5000)

## Customization
- To improve security, store your API key in an environment variable and read it in `app.py`.
- You can further enhance the UI in `static/style.css` and `static/script.js`.

## License
This project is for demonstration and educational purposes.
