import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from main import run_scan

app = Flask(__name__)
CORS(app)

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")

@app.route('/scan', methods=['POST'])
@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    target = data.get('target', '').strip()
    
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target

    results = run_scan(
        target,
        use_nmap=data.get('use_nmap', False),
        use_subdomains=data.get('use_subdomains', True),
        use_ports=data.get('use_ports', True)
    )

    # Auto-save HTML report
    try:
        from modules.reportgen import generate_report
        generate_report(results)
    except Exception as e:
        print(f"Report generation failed: {e}")

    return jsonify(results)
@app.route('/reports', methods=['GET'])
def list_reports():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    files = sorted(os.listdir(REPORTS_DIR), reverse=True)
    return jsonify(files)

@app.route('/reports/<filename>', methods=['GET'])
def get_report(filename):
    return send_from_directory(REPORTS_DIR, filename)

if __name__ == '__main__':
    app.run(debug=True, port=5000)