import os
import re
import sys
import json
import requests
from datetime import datetime

API_KEY = os.getenv("VT_API_KEY", "YOUR_VIRUSTOTAL_API_KEY")

HEADERS = {
    "accept": "application/json",
    "x-apikey": API_KEY
}

BASE_URL = "https://www.virustotal.com/api/v3"

def detect_ioc_type(ioc):
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    sha256_pattern = r"^[a-fA-F0-9]{64}$"
    md5_pattern = r"^[a-fA-F0-9]{32}$"
    
    if re.match(ip_pattern, ioc):
        return "ip_addresses"
    elif re.match(sha256_pattern, ioc) or re.match(md5_pattern, ioc):
        return "files"
    else:
        return "domains"

def scan_ioc(ioc):
    ioc_type = detect_ioc_type(ioc)
    url = f"{BASE_URL}/{ioc_type}/{ioc}"
    
    print(f"\n[*] Scanning IOC: {ioc} (Type: {ioc_type[:-1].upper()})...")
    
    try:
        response = requests.get(url, headers=HEADERS)
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless = stats.get('harmless', 0)
            undetected = stats.get('undetected', 0)
            
            if malicious > 5:
                assessment = "HIGH RISK / MALICIOUS"
            elif malicious > 0 or suspicious > 2:
                assessment = "SUSPICIOUS"
            else:
                assessment = "CLEAN / LOW RISK"
            
            print("-" * 45)
            print("                TRIAGE RESULT                ")
            print("-" * 45)
            print(f" [+] Malicious Engine Detections: {malicious}")
            print(f" [!] Suspicious Detections      : {suspicious}")
            print(f" [-] Harmless / Clean           : {harmless}")
            print(f" [?] Undetected                 : {undetected}")
            print(f" [i] Assessment                 : {assessment}")
            print("-" * 45)
            
            # Save Report to JSON file
            result_data = {
                "ioc": ioc,
                "type": ioc_type[:-1],
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "stats": stats,
                "assessment": assessment
            }
            
            report_filename = f"report_{ioc.replace('.', '_')}.json"
            with open(report_filename, "w") as f:
                json.dump(result_data, f, indent=4)
            print(f" [💾] Report saved successfully as: {report_filename}")
            
        elif response.status_code == 404:
            print("[-] Indicator not found in VirusTotal database.")
        elif response.status_code == 401:
            print("[!] Error: Invalid API Key. Please check your credentials.")
        else:
            print(f"[!] Error HTTP {response.status_code}: {response.text}")
            
    except Exception as e:
        print(f"[!] Connection Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        choice = input("Enter single IOC or press Enter for bulk mode: ").strip()
        if choice:
            scan_ioc(choice)
        else:
            print("Usage for Bulk Scan: python3 ioc_scanner.py -f iocs.txt")
    elif sys.argv[1] == "-f" and len(sys.argv) > 2:
        file_path = sys.argv[2]
        if os.path.exists(file_path):
            print(f"[*] Reading bulk IOCs from {file_path}...")
            with open(file_path, "r") as f:
                iocs = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            for ioc in iocs:
                scan_ioc(ioc)
                print("\n" + "="*50 + "\n")
        else:
            print(f"[!] Error: File '{file_path}' not found.")
    else:
        scan_ioc(sys.argv[1].strip())

