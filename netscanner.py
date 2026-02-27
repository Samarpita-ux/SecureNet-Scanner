#!/usr/bin/env python3
# netscanner.py - Interactive and upgraded network scanner with CVE lookup
# Author: Samarpita Sharma

import socket
import requests
import re
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# ── CONFIG ──────────────────────────────────────────
TIMEOUT = 0.5
DEFAULT_THREADS = 30
DEFAULT_PORTS = list(range(1, 1025))
DEFAULT_TARGET = "scanme.nmap.org"

SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 6667: "IRC", 8080: "HTTP-Alt"
}

# ── FUNCTIONS ───────────────────────────────────────
def scan_port(ip, port):
    try:
        with socket.socket() as s:
            s.settimeout(TIMEOUT)
            return s.connect_ex((ip, port)) == 0
    except:
        return False

def get_service(port):
    return SERVICES.get(port, "Unknown")

def grab_banner(ip, port):
    try:
        with socket.socket() as s:
            s.settimeout(2)
            s.connect((ip, port))
            if port in [80, 8080]:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            else:
                s.send(b"\r\n")
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner.split("\n")[0].strip() if banner else "No banner"
    except:
        return "Could not grab banner"

def parse_banner(banner):
    patterns = {
        "OpenSSH": r"OpenSSH[_-](\d+\.\d+(\.\d+)?)",
        "Apache": r"Apache/(\d+\.\d+(\.\d+)?)",
        "Nginx": r"nginx/(\d+\.\d+(\.\d+)?)",
        "MySQL": r"MySQL[_-](\d+\.\d+(\.\d+)?)"
    }
    for product, regex in patterns.items():
        match = re.search(regex, banner, re.IGNORECASE)
        if match:
            return product, match.group(1)
    return banner, None

def lookup_cves(product, version=None):
    if not product:
        return []
    try:
        search_term = f"{product} {version}" if version else product
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={search_term}&resultsPerPage=3"
        response = requests.get(url, timeout=10)
        data = response.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            desc = cve["descriptions"][0]["value"][:120]
            score, severity = "N/A", "N/A"
            try:
                score = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
                severity = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
            except:
                try:
                    score = cve["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"]
                    severity = cve["metrics"]["cvssMetricV2"][0]["baseSeverity"]
                except:
                    pass
            cves.append({"cve_id": cve["id"], "score": score, "severity": severity, "description": desc})
        return cves
    except:
        return []

def scan_port_thread(ip, port):
    if scan_port(ip, port):
        banner = grab_banner(ip, port)
        product, version = parse_banner(banner)
        cves = lookup_cves(product, version)
        return {
            "port": port,
            "service": get_service(port),
            "banner": banner,
            "product": product,
            "version": version,
            "cves": cves
        }
    return None

# ── INTERACTIVE INPUT ──────────────────────────────
def get_user_input():
    print("\n--- NetScan Pro Interactive Mode ---\n")
    target = input(f"Enter target (default: {DEFAULT_TARGET}): ").strip()
    if not target:
        target = DEFAULT_TARGET

    ports_input = input("Enter ports to scan (comma-separated, default 1-1024): ").strip()
    if ports_input:
        try:
            ports = [int(p.strip()) for p in ports_input.split(",") if p.strip().isdigit()]
        except:
            ports = DEFAULT_PORTS
    else:
        ports = DEFAULT_PORTS

    threads_input = input(f"Enter number of threads (default {DEFAULT_THREADS}): ").strip()
    try:
        threads = int(threads_input) if threads_input else DEFAULT_THREADS
    except:
        threads = DEFAULT_THREADS

    return target, ports, threads

# ── MAIN ────────────────────────────────────────────
def main():
    target, ports, threads = get_user_input()

    print("\n" + "="*60)
    print("           NetScan Pro - Upgraded Scanner")
    print("="*60)
    print(f"Target   : {target}")
    print(f"Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Scanning : ports {ports[0]}-{ports[-1]} using {threads} threads")
    print("="*60)

    try:
        ip = socket.gethostbyname(target)
        print(f"Resolved : {ip}\n")
    except:
        print("Could not resolve target!")
        return

    open_ports = []

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(lambda p: scan_port_thread(ip, p), ports)

    for res in results:
        if res:
            open_ports.append(res)
            print(f"[OPEN] Port {res['port']} → {res['service']} ({res['banner']})")
            if res["cves"]:
                print(f"      CVEs found: {len(res['cves'])}")
            else:
                print(f"      No CVEs found")

    report = {"target": target, "ip": ip, "scan_time": datetime.now().isoformat(), "open_ports": open_ports}
    with open("netscan_report.json", "w") as f:
        json.dump(report, f, indent=4)

    print("\n" + "="*60)
    print(f"Scan complete! {len(open_ports)} open ports found.")
    print("Report saved to netscan_report.json")
    print("="*60)

if __name__ == "__main__":
    main()
    