🛡️ Scanner
A modular web reconnaissance and vulnerability orchestrator. This tool automates the heavy lifting of security auditing by combining multiple scanning techniques into a single workflow.

📂 Project Structure
It is organized as a flat-module system for maximum transparency:

main.py: The central brain. It handles user input, triggers modules, and manages data flow.

headerscanner.py: Checks for missing security headers (HSTS, X-Frame-Options, etc.).

sqlinjection.py & xsstest.py: Targeted scanners for common web vulnerabilities.

portscanner.py: Scans for open services (supports both native Python and Nmap).

cmsdetect.py: Identifies platforms like WordPress, Joomla, or Drupal.

directoryscan.py & subdomainscanner.py: Maps out the target's hidden attack surface.

reportgen.py: Converts raw scan data into professional HTML reports.

🚀 Getting Started
1. Installation
Ensure you are in the PROJECT directory and run:

Bash
pip install -r requirements.txt
2. Usage
Start the interactive scanning process:

Bash
python main.py
3. Output
Check the /reports folder after a scan completes. You'll find:

JSON files: For data logs and integration.

HTML reports: For human-readable summaries.

⚙️ Configuration
You can toggle the following features during the startup prompt:

Nmap Integration: Deeper port scanning (requires Nmap installed on your OS).

Subdomain Brute-forcing: Discovers non-public sub-assets.

Port Scanning: Quick check for common open ports.

⚠️ Legal Notice
Scanner is intended for authorized security testing and educational purposes only. Do not use this tool against any infrastructure you do not have explicit, written permission to test. The author is not responsible for any misuse or damage caused by this program.
