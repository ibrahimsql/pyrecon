# -*- coding: utf-8 -*-
import argparse
import time
import json
import sqlite3
import signal
import sys
import platform
import logging
import random
from datetime import datetime
from colorama import Fore, Style, init
import csv
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from googlesearch import search
from urllib.parse import urlparse
import requests
import httpx
import hashlib
import http.client
from bs4 import BeautifulSoup
import os
import subprocess
from threading import Thread
from queue import Queue
import schedule
import threading
from urllib3.exceptions import InsecureRequestWarning
# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
# Initialize colorama
init(autoreset=True)

# Color definitions
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Style.RESET_ALL
CYAN = Fore.CYAN
MAGENTA = Fore.MAGENTA
YELLOW = Fore.YELLOW
BLUE = Fore.BLUE
LIGHT_BLUE = Fore.LIGHTBLUE_EX
WHITE = Fore.WHITE
PURPLE = Fore.MAGENTA

# Define a custom emoji message
emoji_message = "\U0001F496" + " ❤️  Öykü & İbrahim  ❤️ " + "\U0001F496"

# Create a futuristic-looking banner with enhanced design
banner = rf"""
{CYAN}  
=============================================================================
{MAGENTA}                   {emoji_message}
                   {RED}💖 Kalbimde Sonsuza Dek Olacaksın, Öykü'm 💖
{LIGHT_BLUE}       — You will forever remain in my heart
                {YELLOW}✨ With Infinite Love ✨ {RESET}
===============================================================================
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                    🌟 PyRecon v3.1.4 🌟
        Advanced Google Dork Scanner & Vulnerability Detector
                Created with ❤️ by İbrahim
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""
# Print banner on execution
print(banner)
# Argument Parsing with all possible options
parser = argparse.ArgumentParser(description=" Ultimate Ultra-God VIP Google Dork Search Tool with Extended Vulnerability Detection ")
parser.add_argument("-q", "--query", type=str, nargs='+', required=False, help="Google Dork query or queries (multiple allowed)")
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
parser.add_argument("--nmap", action="store_true", help="Belirtilen domain/IP için Nmap taraması yap")
parser.add_argument("--nmap-ports", type=str, default=None, help="Taranacak port aralığı (örn. '80,443' veya '1-65535')")
parser.add_argument("--nmap-detailed", action="store_true", help="Detaylı Nmap taramasını etkinleştir")
parser.add_argument("--nmap-output-dir", type=str, default=".", help="Nmap tarama çıktılarının kaydedileceği dizin")
parser.add_argument("--nmap-flags", type=str, nargs='+', help="Ek Nmap bayrakları (örn. '-sS', '-A')")
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

# User Agent listesi
user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15'
]

def get_random_user_agent():
    return random.choice(user_agents)

def version_check(version="v3.1.4", check_url="https://api.github.com/repos/ibrahimsql/pyrecon/releases/latest"):
    """
    Versiyon kontrolü yapar ve yeni bir güncelleme olup olmadığını kontrol eder.
    Args:
        version (str): Mevcut yazılım sürümü.
        check_url (str): Son sürüm bilgilerini almak için API endpoint'i.
    Returns:
        None
    """
    logging.info("Versiyon kontrolü başlatılıyor...")
    try:
        # API isteği gönderme
        response = requests.get(check_url, timeout=10)
        if response.status_code == 200:
            logging.info(f"Başarılı yanıt alındı. Status Code: {response.status_code}")
                        # Yanıt JSON formatında mı kontrol et
            content_type = response.headers.get('Content-Type', '')
            if 'application/json' in content_type:
                try:
                    data = response.json()
                    logging.debug(f"JSON Yanıtı: {data}")
                                        # En son sürüm tag'ini al
                    latest_version = data.get('tag_name')
                    if not latest_version:
                        logging.error("'tag_name' bilgisi JSON'da bulunamadı.")
                        print("[ERROR]: En son sürüm bilgisi alınamadı.")
                        return
                                        # Sürüm karşılaştırması
                    if latest_version == version:
                        logging.info(f"Mevcut sürüm ({version}) güncel.")
                        print(f"[Version]: Mevcut sürüm ({version}) en güncel sürümdür.")
                    else:
                        logging.warning(f"Mevcut sürüm ({version}) güncel değil. En son sürüm: {latest_version}")
                        print(f"[INFO]: Yeni bir sürüm mevcut: {latest_version}.")
                        print(f"[INFO]: Güncellemek için: pip install --upgrade ibrahimsql")
                except json.JSONDecodeError as e:
                    logging.error(f"JSON ayrıştırma hatası: {e}")
                    print("[ERROR]: Yanıt geçerli bir JSON değil.")
            else:
                logging.warning("Yanıt JSON formatında değil.")
                print("[INFO]: Yanıt JSON formatında olmadığı için kontrol yapılamadı.")
        else:
            logging.error(f"API isteği başarısız oldu. HTTP Status Code: {response.status_code}")
            print(f"[ERROR]: Sürüm bilgisi alınamadı. Status Code: {response.status_code}")
    except requests.Timeout:
        logging.error("API isteği zaman aşımına uğradı.")
        print("[ERROR]: API isteği zaman aşımına uğradı. Lütfen internet bağlantınızı kontrol edin ve tekrar deneyin.")
    except requests.ConnectionError as e:
        logging.error(f"Bağlantı hatası oluştu: {e}")
        print("[ERROR]: Bağlantı hatası oluştu. İnternet bağlantınızı kontrol edin.")
    except requests.RequestException as e:
        logging.error(f"İstek sırasında bir hata oluştu: {e}")
        print("[ERROR]: Güncelleme kontrolü sırasında bir hata oluştu.")
# Fonksiyonu çağırarak işlemi başlatma
version_check()
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
    "This website is using a security service to protect itself from online attacks"
]
# Advanced vulnerability patterns and paths
vulnerable_paths = [
    '/admin',
    '/admin/dashboard',
    '/phpmyadmin',
    '/wp-admin',
    '/wp-login.php',
    '/administrator',
    '/admin/config.php',
    '/admin/db.php',
    '/backup',
    '/backup.sql',
    '/db.sql',
    '/.env',
    '/.git/config',
    '/api/v1/docs',
    '/api/swagger',
    '/config.php',
    '/info.php',
    '/phpinfo.php',
    '/test.php',
    '/server-status',
    '/wp-config.php',
    '/wp-content/debug.log',
    '/wp-content/uploads',
    '/xmlrpc.php',
]

# Common web vulnerabilities and their patterns
vulnerability_patterns = {
    'SQL Injection': [
        r"'.*OR.*'1'.*='.*1",
        r"admin'.*--",
        r".*UNION.*SELECT.*",
        r".*CONCAT.*\(",
    ],
    'XSS': [
        r"<script.*>",
        r"javascript:",
        r"onload=",
        r"onerror=",
    ],
    'File Inclusion': [
        r"\.\.\/",
        r"\/etc\/passwd",
        r"c:\\windows\\",
    ],
    'Command Injection': [
        r";&.*",
        r"\|.*",
        r"`.*`",
    ]
}

# HTTP Response codes and their meanings
http_status_codes = {
    200: "OK - Standard response for successful HTTP requests",
    201: "Created - Request has been fulfilled",
    301: "Moved Permanently - This and all future requests redirected",
    302: "Found - Temporary redirect",
    400: "Bad Request - Server cannot process due to client error",
    401: "Unauthorized - Authentication is required",
    403: "Forbidden - Server refuses to authorize",
    404: "Not Found - Requested resource could not be found",
    500: "Internal Server Error - Generic error message",
    503: "Service Unavailable - Server temporarily unavailable"
}

class VulnerabilityScanner:
    """Advanced vulnerability scanner with multiple detection methods"""
    
    def __init__(self):
        self.results = []
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close'
        }
        self.timeout = 10
        self.max_retries = 3
        
    def scan_url(self, url):
        """Perform comprehensive vulnerability scan on a URL"""
        results = {
            'url': url,
            'vulnerabilities': [],
            'security_headers': {},
            'response_time': None,
            'status_code': None,
            'server_info': None
        }
        
        try:
            start_time = time.time()
            response = requests.get(
                url, 
                headers=self.headers,
                timeout=self.timeout,
                verify=True
            )
            results['response_time'] = time.time() - start_time
            results['status_code'] = response.status_code
            results['server_info'] = response.headers.get('Server')
            
            # Check security headers
            security_headers = [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection'
            ]
            
            for header in security_headers:
                results['security_headers'][header] = response.headers.get(header)
            
            # Check for common vulnerabilities
            content = response.text.lower()
            for vuln_type, patterns in vulnerability_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        results['vulnerabilities'].append({
                            'type': vuln_type,
                            'pattern': pattern,
                            'severity': 'High'
                        })
            
            return results
            
        except requests.exceptions.SSLError:
            return {'error': 'SSL/TLS verification failed', 'url': url}
        except requests.exceptions.Timeout:
            return {'error': 'Connection timed out', 'url': url}
        except requests.exceptions.RequestException as e:
            return {'error': str(e), 'url': url}

class ReportGenerator:
    """Generate comprehensive security reports"""
    
    def __init__(self, results, output_file):
        self.results = results
        self.output_file = output_file
        self.report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
    def generate_html_report(self):
        """Generate a detailed HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background: #f8f9fa; padding: 20px; border-radius: 5px; }
                .vulnerability { margin: 10px 0; padding: 10px; border-left: 4px solid #dc3545; }
                .high { border-color: #dc3545; }
                .medium { border-color: #ffc107; }
                .low { border-color: #28a745; }
                table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background-color: #f8f9fa; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Scan Report</h1>
                <p>Generated on: {timestamp}</p>
            </div>
            
            <h2>Scan Summary</h2>
            <table>
                <tr><th>Total URLs Scanned</th><td>{total_urls}</td></tr>
                <tr><th>Vulnerabilities Found</th><td>{total_vulns}</td></tr>
                <tr><th>Scan Duration</th><td>{duration}</td></tr>
            </table>
            
            <h2>Detailed Findings</h2>
            {detailed_findings}
        </body>
        </html>
        """
        
        # Generate detailed findings HTML
        detailed_findings = ""
        for result in self.results:
            if 'vulnerabilities' in result:
                for vuln in result['vulnerabilities']:
                    severity_class = 'high' if vuln['severity'] == 'High' else 'medium'
                    detailed_findings += f"""
                    <div class="vulnerability {severity_class}">
                        <h3>{vuln['type']}</h3>
                        <p>URL: {result['url']}</p>
                        <p>Severity: {vuln['severity']}</p>
                        <p>Pattern: {vuln['pattern']}</p>
                    </div>
                    """
        
        # Calculate summary statistics
        total_urls = len(self.results)
        total_vulns = sum(len(r.get('vulnerabilities', [])) for r in self.results)
        
        # Generate final report
        report_html = html_template.format(
            timestamp=self.report_time,
            total_urls=total_urls,
            total_vulns=total_vulns,
            duration="N/A",
            detailed_findings=detailed_findings
        )
        
        # Save report
        with open(f"{self.output_file}.html", 'w') as f:
            f.write(report_html)
            
    def generate_json_report(self):
        """Generate a JSON format report"""
        report_data = {
            'timestamp': self.report_time,
            'summary': {
                'total_urls': len(self.results),
                'total_vulnerabilities': sum(len(r.get('vulnerabilities', [])) for r in self.results),
            },
            'detailed_results': self.results
        }
        
        with open(f"{self.output_file}.json", 'w') as f:
            json.dump(report_data, f, indent=4)
            
    def generate_csv_report(self):
        """Generate a CSV format report"""
        with open(f"{self.output_file}.csv", 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['URL', 'Vulnerability Type', 'Severity', 'Pattern', 'Status Code'])
            
            for result in self.results:
                if 'vulnerabilities' in result:
                    for vuln in result['vulnerabilities']:
                        writer.writerow([
                            result['url'],
                            vuln['type'],
                            vuln['severity'],
                            vuln['pattern'],
                            result.get('status_code', 'N/A')
                        ])

class AdvancedSearch:
    """Advanced search capabilities with multiple search engines"""
    
    def __init__(self):
        self.search_engines = {
            'google': self._google_search,
            'bing': self._bing_search,
            'duckduckgo': self._duckduckgo_search
        }
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        
    def _google_search(self, query, num_results=10):
        """Perform Google search with advanced options"""
        try:
            results = []
            for url in search(query, num_results=num_results, stop=num_results, pause=2):
                results.append(url)
            return results
        except Exception as e:
            logging.error(f"Google search error: {str(e)}")
            return []
            
    def _bing_search(self, query, num_results=10):
        """Perform Bing search"""
        base_url = "https://www.bing.com/search"
        results = []
        
        try:
            for i in range(0, num_results, 10):
                params = {
                    'q': query,
                    'first': i
                }
                response = requests.get(base_url, params=params, headers=self.headers)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                for link in soup.find_all('a', href=True):
                    url = link['href']
                    if url.startswith('http') and not url.startswith('http://go.microsoft.com'):
                        results.append(url)
                        if len(results) >= num_results:
                            break
                            
            return results[:num_results]
        except Exception as e:
            logging.error(f"Bing search error: {str(e)}")
            return []
            
    def _duckduckgo_search(self, query, num_results=10):
        """Perform DuckDuckGo search"""
        base_url = "https://duckduckgo.com/html/"
        results = []
        
        try:
            params = {'q': query}
            response = requests.get(base_url, params=params, headers=self.headers)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for link in soup.find_all('a', class_='result__url'):
                url = link['href']
                if url.startswith('http'):
                    results.append(url)
                    if len(results) >= num_results:
                        break
                        
            return results[:num_results]
        except Exception as e:
            logging.error(f"DuckDuckGo search error: {str(e)}")
            return []
            
    def multi_engine_search(self, query, engines=None, num_results=10):
        """Perform search across multiple engines"""
        if engines is None:
            engines = list(self.search_engines.keys())
            
        all_results = set()
        for engine in engines:
            if engine in self.search_engines:
                try:
                    results = self.search_engines[engine](query, num_results)
                    all_results.update(results)
                    logging.info(f"Found {len(results)} results from {engine}")
                except Exception as e:
                    logging.error(f"Error in {engine} search: {str(e)}")
                    
        return list(all_results)

class WAFDetector:
    """Web Application Firewall (WAF) detection capabilities"""
    
    def __init__(self):
        self.waf_signatures = {
            'Cloudflare': [
                'Cloudflare Ray ID:',
                'Attention Required! | Cloudflare',
                '__cfduid'
            ],
            'ModSecurity': [
                'ModSecurity Action',
                'ModSecurity CRS',
                'This error was generated by Mod_Security'
            ],
            'Imperva': [
                'Incapsula incident ID',
                '_incap_ses',
                'X-Iinfo'
            ],
            'Akamai': [
                'AkamaiGHost',
                'X-Akamai-',
                'akamaighost'
            ]
        }
        
    def detect_waf(self, response):
        """Detect WAF presence from response"""
        detected_wafs = []
        
        # Check headers
        headers = str(response.headers).lower()
        # Check cookies
        cookies = str(response.cookies).lower()
        # Check content
        content = response.text.lower()
        
        for waf_name, signatures in self.waf_signatures.items():
            for signature in signatures:
                if (signature.lower() in headers or
                    signature.lower() in cookies or
                    signature.lower() in content):
                    detected_wafs.append(waf_name)
                    break
                    
        return list(set(detected_wafs))

class DorkScanner:
    def __init__(self):
        """Initialize DorkScanner with enhanced features"""
        self.results = []
        self.conn, self.cursor = init_db(f"{args.output}.db") if args.output_format == "db" else (None, None)
        self.success_count = 0
        self.fail_count = 0
        self.total_scanned = 0
        self.start_time = time.time()
        self.vulnerable_urls = []
        self.protected_urls = []
        self.vuln_scanner = VulnerabilityScanner()
        self.waf_detector = WAFDetector()
        self.advanced_search = AdvancedSearch()
        self.num_results = args.num_results if hasattr(args, 'num_results') else 10
        self.timeout = args.timeout if hasattr(args, 'timeout') else 5
        self.custom_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0",
            "DNT": "1"
        }
        
    def save_results(self):
        """Save scan results in multiple formats"""
        if not self.results:
            print(f"{Fore.YELLOW}[WARNING] No results to save{Style.RESET_ALL}")
            return
            
        # Create report generator
        report_gen = ReportGenerator(self.results, args.output)
        
        try:
            if args.output_format == 'html':
                report_gen.generate_html_report()
            elif args.output_format == 'json':
                report_gen.generate_json_report()
            elif args.output_format == 'csv':
                report_gen.generate_csv_report()
            elif args.output_format == 'db':
                self._save_to_database()
                
            print(f"{Fore.GREEN}[SUCCESS] Results saved to {args.output}.{args.output_format}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to save results: {str(e)}{Style.RESET_ALL}")
            
    def _save_to_database(self):
        """Save results to SQLite database"""
        if not self.conn or not self.cursor:
            raise Exception("Database connection not initialized")
            
        try:
            for result in self.results:
                self.cursor.execute(
                    """
                    INSERT INTO results (domain, source_url, status_code, vulnerable_paths)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        urlparse(result['url']).netloc,
                        result['url'],
                        result.get('status_code'),
                        json.dumps(result.get('vulnerabilities', []))
                    )
                )
            self.conn.commit()
            
        except sqlite3.Error as e:
            raise Exception(f"Database error: {str(e)}")
    
    def print_banner(self):
        print(Fore.MAGENTA + """
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                    🌟 PyRecon v3.1.4 🌟
        Advanced Google Dork Scanner & Vulnerability Detector
                Created with ❤️ by Your Name
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
""" + Style.RESET_ALL)

    def print_progress(self, current, total, prefix='', suffix='', decimals=1, length=50, fill='█', printEnd="\r"):
        percent = ("{0:." + str(decimals) + "f}").format(100 * (current / float(total)))
        filledLength = int(length * current // total)
        bar = fill * filledLength + '-' * (length - filledLength)
        print(f'\r{prefix} |{bar}| {percent}% {suffix}', end=printEnd)
        if current == total:
            print()

    def check_security_headers(self, response):
        security_headers = {
            'X-XSS-Protection': 'XSS Protection',
            'X-Content-Type-Options': 'Content Type Options',
            'X-Frame-Options': 'Frame Options',
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP'
        }
        missing_headers = []
        for header, name in security_headers.items():
            if header not in response.headers:
                missing_headers.append(name)
        return missing_headers

    def analyze_response(self, response):
        analysis = {
            'server': response.headers.get('Server', 'Unknown'),
            'powered_by': response.headers.get('X-Powered-By', 'Not disclosed'),
            'missing_headers': self.check_security_headers(response),
            'cookies': len(response.cookies),
            'response_time': response.elapsed.total_seconds()
        }
        return analysis

    def print_result(self, url, status, message, vuln_type=None):
        current_time = datetime.now().strftime("%H:%M:%S")
        if status == "SUCCESS":
            color = Fore.GREEN
            self.success_count += 1
        elif status == "WARNING":
            color = Fore.YELLOW
        elif status == "VULNERABLE":
            color = Fore.RED
            self.vulnerable_urls.append((url, vuln_type))
        else:
            color = Fore.RED
            self.fail_count += 1

        print(f"{color}[{current_time}] [{status}] {message}{Style.RESET_ALL}")

    def check_for_ddos_protection(self, url):
        try:
            headers = {**self.custom_headers, "User-Agent": get_random_user_agent()}
            proxies = get_random_proxy() if args.proxy_rotator else None
            
            self.print_result(url, "INFO", f"🔍 Checking protection on {url}")
            response = requests.get(url, headers=headers, proxies=proxies, timeout=args.timeout)
            
            analysis = self.analyze_response(response)
            
            if any(phrase in response.text.lower() for phrase in ddos_warning_phrases):
                self.print_result(url, "WARNING", f"🛡️ DDoS protection detected on {url}")
                self.protected_urls.append(url)
                return True, response.status_code
            
            if analysis['missing_headers']:
                self.print_result(url, "WARNING", f"⚠️ Missing security headers: {', '.join(analysis['missing_headers'])}")
            
            self.print_result(url, "SUCCESS", f"✅ No DDoS protection found on {url}")
            return False, response.status_code
            
        except requests.exceptions.Timeout:
            self.print_result(url, "ERROR", f"⏰ Timeout while checking {url}")
        except requests.exceptions.ConnectionError:
            self.print_result(url, "ERROR", f"🔌 Connection error for {url}")
        except requests.exceptions.RequestException as e:
            self.print_result(url, "ERROR", f"❌ Error checking {url}: {str(e)}")
        return True, None

    def scan_vulnerable_paths(self, domain):
        found_paths = []
        total_paths = len(vulnerable_paths)
        
        print(f"\n{Fore.CYAN}🔍 Scanning {domain} for {total_paths} potential vulnerabilities...{Style.RESET_ALL}\n")
        
        for i, path in enumerate(vulnerable_paths, 1):
            url = f"https://{domain}{path}"
            try:
                headers = {**self.custom_headers, "User-Agent": get_random_user_agent()}
                proxies = get_random_proxy() if args.proxy_rotator else None
                
                self.print_progress(i, total_paths, prefix='Progress:', suffix='Complete', length=50)
                
                response = requests.get(url, headers=headers, proxies=proxies, timeout=args.timeout)
                
                if response.status_code == 200:
                    vuln_type = path.split('/')[-1]
                    self.print_result(url, "VULNERABLE", f"💀 Found vulnerable path: {path}", vuln_type)
                    found_paths.append({"path": url, "type": vuln_type})
                    
                time.sleep(random.uniform(args.min_delay, args.max_delay))
                
            except requests.exceptions.RequestException:
                continue
        
        if found_paths:
            print(f"\n{Fore.GREEN}🎯 Found {len(found_paths)} vulnerable paths on {domain}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.BLUE}✅ No vulnerable paths found on {domain}{Style.RESET_ALL}")
        
        return found_paths

    def process_result(self, result):
        try:
            domain = urlparse(result).netloc
            if args.remove_www:
                domain = domain.replace("www.", "")
            
            if not domain.endswith(f".{args.tld}"):
                self.print_result(domain, "SKIP", f"⏭️ Domain TLD doesn't match {args.tld}")
                return None
            
            print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}🎯 Processing: {domain}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")
            
            if args.waf_bypass:
                self.print_result(domain, "INFO", "🛡️ Attempting WAF bypass...")
                headers = {**self.custom_headers, 
                         "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                         "X-Real-IP": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"}
            
            if args.check_cloudflare:
                is_protected, _ = self.check_for_ddos_protection(result)
                if is_protected:
                    self.print_result(domain, "SKIP", "🛡️ Cloudflare protection detected")
                    return None
            
            vulnerable_paths = self.scan_vulnerable_paths(domain)
            
            result_data = {
                "domain": domain,
                "source_url": result,
                "vulnerable_paths": vulnerable_paths,
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            self.results.append(result_data)
            self.total_scanned += 1
            
            return result_data
            
        except Exception as e:
            self.print_result(domain, "ERROR", f"❌ Error processing result: {str(e)}")
            return None

    def print_summary(self):
        duration = time.time() - self.start_time
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📊 Scan Summary{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"🕒 Duration: {duration:.2f} seconds")
        print(f"🎯 Total Scanned: {self.total_scanned}")
        print(f"✅ Successful: {self.success_count}")
        print(f"❌ Failed: {self.fail_count}")
        print(f"💀 Vulnerable URLs Found: {len(self.vulnerable_urls)}")
        print(f"🛡️ Protected URLs Found: {len(self.protected_urls)}")
        
        if self.vulnerable_urls:
            print(f"\n{Fore.RED}🚨 Vulnerable URLs:{Style.RESET_ALL}")
            for url, vuln_type in self.vulnerable_urls:
                print(f"  • {url} ({vuln_type})")

    def google_dork_search(self, dork):
        try:
            logging.info(f"{CYAN}🔍 Starting Google Dork search for: {dork}{RESET}")
            
            results = []
            try:
                for url in search(dork, num_results=self.num_results, timeout=self.timeout):
                    print(f"{GREEN}[+] Found: {url}{RESET}")
                    results.append(url)
                    
                print(f"\n{CYAN}🎯 Found {len(results)} results for dork: {dork}{RESET}\n")
                
                # Her URL için güvenlik taraması yap
                for url in results:
                    try:
                        print(f"\n{YELLOW}================================================================================")
                        print(f"🎯 Processing: {url}")
                        print(f"================================================================================{RESET}\n")
                        
                        self.scan_vulnerable_paths(url)
                        time.sleep(1)  # Rate limiting
                    except Exception as e:
                        logging.error(f"{RED}[ERROR] Error scanning {url}: {str(e)}{RESET}")
                
            except Exception as e:
                logging.error(f"{RED}[ERROR] Search error: {str(e)}{RESET}")
            
            return results
            
        except Exception as e:
            logging.error(f"{RED}[ERROR] Search failed: {str(e)}{RESET}")
            return []

# Scheduler for Automated Scans
def schedule_scan(scanner):
    if args.scheduler:
        try:
            schedule_time = datetime.strptime(args.scheduler, "%H:%M").time()
        except ValueError:
            logging.error("[HATA] Zamanlama için geçersiz format. Doğru format: HH:MM")
            return
        current_time = datetime.now().time()
        if current_time >= schedule_time:
            logging.info(Fore.GREEN + "[SCHEDULER] Starting scheduled scan...")
            for dork in args.query:
                scanner.google_dork_search(dork)
            return
        time.sleep(30)
# Fonksiyonları çağırma
def some_function():
    try:
        logging.info(Fore.YELLOW + "[INFO] Waiting for 30 seconds...")
        time.sleep(30)  # 30 saniye bekler
        logging.info(Fore.GREEN + "[INFO] Waiting time complete!")
    except Exception as e:
        logging.error(Fore.RED + f"[ERROR] Error during sleep: {str(e)}")
some_function()
# Main Function
def main():
    """
    Ana fonksiyon: Dork işlemleri ve sonuçları kaydetme
    """
    scanner = None
    try:
        scanner = DorkScanner()
        scanner.print_banner()  # Her zaman banner'ı göster
        
        # Eğer query veya file parametresi varsa tarama yap
        if args.query:
            for dork in args.query:
                scanner.google_dork_search(dork)
        elif args.file:
            with open(args.file, 'r') as f:
                dorks = f.readlines()
            for dork in dorks:
                scanner.google_dork_search(dork.strip())
        
        # Sonuçları kaydetme
        if args.save:
            try:
                scanner.save_results()
                if args.output and args.output_format:
                    logging.info(f"{MAGENTA}[INFO] Results saved to '{args.output}.{args.output_format}'.{RESET}")
                else:
                    logging.warning(f"{YELLOW}[WARNING] Output file or format not properly defined.{RESET}")
            except Exception as e:
                logging.error(f"{RED}[ERROR] Failed to save results: {str(e)}{RESET}")
            
    except Exception as e:
        logging.error(f"{RED}[ERROR] An error occurred: {str(e)}{RESET}")
    finally:
        # Veritabanı bağlantısını kapatma
        if scanner and scanner.conn:
            scanner.conn.close()
            logging.info(f"{GREEN}[DB] Veritabanı bağlantısı kapatıldı.{RESET}")

if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('scanner.log'),
            logging.StreamHandler()
        ]
    )
    main()
