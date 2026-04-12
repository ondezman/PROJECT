# 🛡️ Scanner

A modular web reconnaissance and vulnerability orchestrator.

This tool automates the heavy lifting of security auditing by combining multiple scanning techniques into a single workflow.

---

## 📂 Project Structure

The project follows a **flat-module architecture** for simplicity and transparency:

- **main.py** → The central controller. Handles user input, triggers modules, and manages data flow.
- **headerscanner.py** → Detects missing security headers (HSTS, X-Frame-Options, etc.).
- **sqlinjection.py & xsstest.py** → Basic vulnerability scanners for SQL Injection and XSS.
- **portscanner.py** → Scans for open ports (Python-based + optional Nmap support).
- **cmsdetect.py** → Identifies CMS platforms (WordPress, Joomla, Drupal, etc.).
- **directoryscan.py & subdomainscanner.py** → Maps hidden attack surface (directories + subdomains).
- **reportgen.py** → Generates structured HTML reports from scan results.

---

## 🚀 Getting Started

### 1. Installation

Ensure you are in the **project root directory**, then install dependencies:

bash
pip install -r requirements.txt

2. Usage

Start the interactive scanner:

python main.py
3. Output

After each scan, results are saved in the /reports directory:

📄 JSON files → Raw structured scan data
🌐 HTML reports → Human-readable vulnerability summary
📦 Requirements

Create a requirements.txt file with:

requests
beautifulsoup4
lxml
python-nmap
⚙️ Configuration

During startup, you can enable or disable:

🛰️ Nmap Integration → Advanced port scanning (requires Nmap installed)
🌍 Subdomain Brute Force → Discover hidden assets
🔌 Port Scanning → Quick service enumeration
🧠 Modules Overview

The scanner is composed of independent modules:

headerscanner.py → Security header analysis
sqlinjection.py → SQL Injection testing
xsstest.py → XSS detection
portscanner.py → Port scanning (Python + Nmap)
cmsdetect.py → CMS fingerprinting
directoryscan.py → Hidden directory discovery
subdomainscanner.py → Subdomain enumeration
reportgen.py → HTML report generator
⚠️ Legal Notice

This tool is intended for authorized security testing and educational purposes only.

Do not use it against any system you do not own or have explicit written permission to test.

The author is not responsible for any misuse or damage caused by this tool.
