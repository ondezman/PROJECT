import sys
import json
import logging
from datetime import datetime
from urllib.parse import urlparse

from headerscanner import check_headers
from Linkextractor import extract_links
from directoryscan import directory_scan
from sqlinjection import test_sqli
from xsstest import test_xss
from portscanner import port_scan, run_nmap
from subdomainscanner import scan_subdomains
from cmsdetect import detect_cms
from reportgen import generate_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)


def validate_url(url):
    """
    Validates that the URL is a proper http/https URL.

    Args:
        url (str): URL to validate

    Returns:
        bool: True if valid
    """
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def run_scan(url, use_nmap=False, use_subdomains=True, use_ports=True):
    """
    Runs all vulnerability and recon checks on a target URL.

    Args:
        url           (str):  Target website URL
        use_nmap      (bool): Run Nmap scan (requires Nmap installed)
        use_subdomains(bool): Run subdomain brute-force
        use_ports     (bool): Run pure Python port scan

    Returns:
        dict: Full scan results
    """
    if not validate_url(url):
        return {"error": f"Invalid URL: '{url}'. Must start with http:// or https://"}

    parsed = urlparse(url)
    host   = parsed.hostname

    results = {
        "meta": {
            "target":    url,
            "host":      host,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
    }

    checks = {
        "headers":     lambda: check_headers(url),
        "links":       lambda: extract_links(url),
        "directories": lambda: directory_scan(url),
        "cms":         lambda: detect_cms(url),
    }

    if use_ports:
        checks["ports"] = lambda: port_scan(url)

    if use_subdomains:
        checks["subdomains"] = lambda: scan_subdomains(url)

    if use_nmap:
        checks["nmap"] = lambda: run_nmap(url)
    else:
        results["nmap"] = {"skipped": "Nmap disabled. Pass use_nmap=True to enable."}

    if "?" in url:
        checks["sqli"] = lambda: test_sqli(url)
        checks["xss"]  = lambda: test_xss(url)
    else:
        results["sqli"] = {"skipped": "No query parameters detected in URL"}
        results["xss"]  = {"skipped": "No query parameters detected in URL"}
        log.info("SQLi and XSS skipped — no query parameters")

    for name, check in checks.items():
        log.info("Running %s...", name)
        try:
            results[name] = check()
            log.info("%s complete", name)
        except Exception as e:
            log.error("%s failed: %s", name, e)
            results[name] = {"error": str(e)}

    return results


def print_results(results):
    """
    Pretty-prints scan results to stdout.

    Args:
        results (dict): Scan results from run_scan()
    """
    if "error" in results:
        print(f"\n[ERROR] {results['error']}")
        return

    meta = results.get("meta", {})
    print(f"\n{'='*60}")
    print(f"  TARGET    : {meta.get('target')}")
    print(f"  HOST      : {meta.get('host')}")
    print(f"  TIMESTAMP : {meta.get('timestamp')}")
    print(f"{'='*60}\n")

    for key, value in results.items():
        if key == "meta":
            continue

        print(f"[ {key.upper()} ]")

        if isinstance(value, dict):
            if "error" in value:
                print(f"  ERROR: {value['error']}")
            elif "skipped" in value:
                print(f"  SKIPPED: {value['skipped']}")
            elif key == "ports":
                for p in value.get("open_ports", []):
                    risk = f" — {p['risk']}" if p.get("risk") else ""
                    print(f"  {p['port']:<6} {p['service']}{risk}")
            elif key == "cms":
                print(f"  Detected : {', '.join(value.get('detected', [])) or 'None'}")
                for r in value.get("risks", []):
                    print(f"  ⚠ {r}")
            elif key == "subdomains":
                for s in value.get("found", []):
                    print(f"  [{s.get('status','?')}] {s.get('url')} ({s.get('ip')})")
            elif key == "nmap":
                print(f"  OS     : {value.get('os_guess') or 'Unknown'}")
                print(f"  Ports  : {', '.join(value.get('open_ports', []))}")
            else:
                for k, v in value.items():
                    if isinstance(v, list):
                        for item in v:
                            print(f"  - {item}")
                    else:
                        print(f"  {k}: {v}")
        elif isinstance(value, list):
            if value:
                for item in value:
                    print(f"  - {item}")
            else:
                print("  No issues found.")
        print()


if __name__ == "__main__":
    target = input("Enter target URL: ").strip()

    print("\nOptions (press Enter to accept default):")
    use_nmap  = input("  Run Nmap? (y/N): ").strip().lower() == "y"
    use_subs  = input("  Run subdomain scan? (Y/n): ").strip().lower() != "n"
    use_ports = input("  Run port scan? (Y/n): ").strip().lower() != "n"

    print()
    scan_results = run_scan(
        target,
        use_nmap=use_nmap,
        use_subdomains=use_subs,
        use_ports=use_ports
    )

    print_results(scan_results)

    save_json = input("Save JSON? (y/N): ").strip().lower() == "y"
    if save_json:
        import os
        reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
        os.makedirs(reports_dir, exist_ok=True)
        filename = os.path.join(reports_dir, f"scan_{urlparse(target).netloc}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json")
        with open(filename, "w") as f:
            json.dump(scan_results, f, indent=2)
        print(f"JSON saved: {filename}")

    save_html = input("Generate HTML report? (Y/n): ").strip().lower() != "n"
    if save_html:
        path = generate_report(scan_results)
        print(f"HTML report saved: {path}")
