import sys
import json
import os
from main import run_scan
from modules.reportgen import generate_report

# Gracefully handle missing or invalid JSON payloads
try:
    data = json.loads(sys.argv[1])
except (IndexError, json.JSONDecodeError):
    print(json.dumps({"error": "Valid JSON payload required as argument"}))
    sys.exit(1)

target = data.get('target')
results = run_scan(
    target,
    use_nmap=data.get('use_nmap', False),
    use_subdomains=data.get('use_subdomains', True),
    use_ports=data.get('use_ports', True)
)

report_file = None
try:
    report_path = generate_report(results)
    report_file = os.path.basename(report_path)
except Exception as e:
    print(f"Report generation failed: {e}", file=sys.stderr)

print(json.dumps({"results": results, "report_file": report_file}))