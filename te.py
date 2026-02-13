#!/usr/bin/env python3
"""
ONIX SCANNER - Simple Web Vulnerability Scanner
A student-friendly security scanning tool
"""

import sys
import argparse
import subprocess
import os
import time
import re
from urllib.parse import urlparse

# ============ COLOR CODES ============
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# ============ BANNER ============
def print_banner():
    banner = f"""
{Colors.WARNING}
   ____        _         _____                                 
  / __ \      (_)       / ____|                                
 | |  | |_ __  ___  __ | (___   ___ __ _ _ __  _ __   ___ _ __ 
 | |  | | '_ \| \ \/ /  \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 | |__| | | | | |>  <   ____) | (_| (_| | | | | | | |  __/ |   
  \____/|_| |_|_/_/\_\ |_____/ \___\__,_|_| |_|_| |_|\___|_|   
                                                                
        Simple Web Vulnerability Scanner v1.0
{Colors.ENDC}
    """
    print(banner)

# ============ HELPER FUNCTIONS ============
def print_help():
    help_text = f"""
{Colors.OKGREEN}USAGE GUIDE:{Colors.ENDC}
    python3 onixscanner.py <target_url>
    
{Colors.OKGREEN}EXAMPLES:{Colors.ENDC}
    python3 onixscanner.py example.com
    python3 onixscanner.py http://testphp.vulnweb.com
    
{Colors.OKGREEN}OPTIONS:{Colors.ENDC}
    --help      Show this help message
    --version   Show version information
"""
    print(help_text)

def clean_url(url):
    """Clean and validate URL"""
    if not url:
        return None
    
    # Add http:// if no protocol specified
    if not re.match(r'https?://', url):
        url = 'http://' + url
    
    try:
        parsed = urlparse(url)
        return parsed.netloc if parsed.netloc else parsed.path
    except:
        return None

def check_internet():
    """Check internet connectivity"""
    try:
        response = os.system("ping -c 1 8.8.8.8 > /dev/null 2>&1")
        return response == 0
    except:
        return False

def check_tool(tool_name):
    """Check if a tool is installed"""
    try:
        subprocess.run([tool_name, '--help'], 
                      stdout=subprocess.PIPE, 
                      stderr=subprocess.PIPE, 
                      timeout=5)
        return True
    except:
        return False

# ============ SCANNING FUNCTIONS ============

class Scanner:
    def __init__(self, target):
        self.target = target
        self.results = []
        self.start_time = time.time()
        
    def print_status(self, message, status="info"):
        """Print colored status messages"""
        color = {
            "info": Colors.OKBLUE,
            "success": Colors.OKGREEN,
            "warning": Colors.WARNING,
            "error": Colors.FAIL
        }.get(status, Colors.ENDC)
        
        print(f"{color}[*] {message}{Colors.ENDC}")
    
    def run_command(self, cmd, timeout=30):
        """Run shell command safely"""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return "TIMEOUT"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def scan_host_info(self):
        """Basic host information check"""
        self.print_status(f"Scanning host information for {self.target}")
        
        # Check if host resolves
        output = self.run_command(f"host {self.target}")
        
        if "has address" in output:
            self.results.append({
                "test": "Host Resolution",
                "status": "PASS",
                "severity": "INFO",
                "details": "Host resolves correctly"
            })
            return True
        else:
            self.results.append({
                "test": "Host Resolution",
                "status": "FAIL",
                "severity": "HIGH",
                "details": "Cannot resolve host"
            })
            return False
    
    def scan_ports(self):
        """Basic port scan using nmap"""
        if not check_tool("nmap"):
            self.print_status("nmap not installed, skipping port scan", "warning")
            return
        
        self.print_status("Scanning common ports (this may take a minute)...")
        
        output = self.run_command(
            f"nmap -F --open {self.target}",
            timeout=120
        )
        
        if "open" in output.lower():
            self.results.append({
                "test": "Port Scan",
                "status": "FOUND",
                "severity": "MEDIUM",
                "details": "Open ports detected. Review manually."
            })
        else:
            self.results.append({
                "test": "Port Scan",
                "status": "PASS",
                "severity": "INFO",
                "details": "No common open ports found"
            })
    
    def scan_http_headers(self):
        """Check HTTP security headers"""
        self.print_status("Checking HTTP security headers...")
        
        output = self.run_command(
            f"curl -I -L --max-time 10 http://{self.target}"
        )
        
        # Check for security headers
        security_headers = {
            "X-Frame-Options": False,
            "X-XSS-Protection": False,
            "X-Content-Type-Options": False,
            "Strict-Transport-Security": False
        }
        
        for header in security_headers.keys():
            if header.lower() in output.lower():
                security_headers[header] = True
        
        missing_headers = [h for h, present in security_headers.items() if not present]
        
        if missing_headers:
            self.results.append({
                "test": "Security Headers",
                "status": "VULNERABLE",
                "severity": "MEDIUM",
                "details": f"Missing headers: {', '.join(missing_headers)}"
            })
        else:
            self.results.append({
                "test": "Security Headers",
                "status": "PASS",
                "severity": "INFO",
                "details": "All security headers present"
            })
    
    def scan_ssl(self):
        """Basic SSL/TLS check"""
        self.print_status("Checking SSL/TLS configuration...")
        
        output = self.run_command(
            f"curl -I --max-time 10 https://{self.target}"
        )
        
        if "SSL" in output or "TLS" in output or output.startswith("HTTP/2"):
            self.results.append({
                "test": "SSL/TLS",
                "status": "PASS",
                "severity": "INFO",
                "details": "SSL/TLS appears to be configured"
            })
        else:
            self.results.append({
                "test": "SSL/TLS",
                "status": "WARNING",
                "severity": "LOW",
                "details": "Could not verify SSL/TLS configuration"
            })
    
    def scan_robots(self):
        """Check robots.txt"""
        self.print_status("Checking robots.txt...")
        
        output = self.run_command(
            f"curl --max-time 10 http://{self.target}/robots.txt"
        )
        
        if "Disallow" in output or "Allow" in output:
            self.results.append({
                "test": "robots.txt",
                "status": "FOUND",
                "severity": "INFO",
                "details": "robots.txt file exists - review for sensitive paths"
            })
        else:
            self.results.append({
                "test": "robots.txt",
                "status": "NOT FOUND",
                "severity": "INFO",
                "details": "No robots.txt file found"
            })
    
    def generate_report(self):
        """Generate scan report"""
        elapsed_time = int(time.time() - self.start_time)
        
        print(f"\n{Colors.BOLD}{'='*60}{Colors.ENDC}")
        print(f"{Colors.BOLD}SCAN REPORT FOR: {self.target}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}\n")
        
        # Group results by severity
        critical = [r for r in self.results if r['severity'] == 'CRITICAL']
        high = [r for r in self.results if r['severity'] == 'HIGH']
        medium = [r for r in self.results if r['severity'] == 'MEDIUM']
        low = [r for r in self.results if r['severity'] == 'LOW']
        info = [r for r in self.results if r['severity'] == 'INFO']
        
        # Print summary
        print(f"{Colors.FAIL}Critical: {len(critical)}{Colors.ENDC}")
        print(f"{Colors.FAIL}High: {len(high)}{Colors.ENDC}")
        print(f"{Colors.WARNING}Medium: {len(medium)}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}Low: {len(low)}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Info: {len(info)}{Colors.ENDC}\n")
        
        # Print detailed results
        for result in self.results:
            severity_color = {
                "CRITICAL": Colors.FAIL,
                "HIGH": Colors.FAIL,
                "MEDIUM": Colors.WARNING,
                "LOW": Colors.OKBLUE,
                "INFO": Colors.OKGREEN
            }.get(result['severity'], Colors.ENDC)
            
            print(f"{severity_color}[{result['severity']}] {result['test']}{Colors.ENDC}")
            print(f"  Status: {result['status']}")
            print(f"  Details: {result['details']}\n")
        
        print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}")
        print(f"Total scan time: {elapsed_time} seconds")
        print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}\n")
        
        # Save to file
        report_file = f"onix_report_{self.target}_{int(time.time())}.txt"
        with open(report_file, 'w') as f:
            f.write(f"ONIX SCANNER REPORT\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Scan Date: {time.ctime()}\n")
            f.write(f"{'='*60}\n\n")
            
            for result in self.results:
                f.write(f"[{result['severity']}] {result['test']}\n")
                f.write(f"Status: {result['status']}\n")
                f.write(f"Details: {result['details']}\n\n")
        
        print(f"{Colors.OKGREEN}Report saved to: {report_file}{Colors.ENDC}")

# ============ MAIN FUNCTION ============
def main():
    """Main function"""
    
    # Clear screen
    os.system('clear' if os.name == 'posix' else 'cls')
    
    # Print banner
    print_banner()
    
    # Parse arguments
    if len(sys.argv) < 2 or '--help' in sys.argv:
        print_help()
        sys.exit(0)
    
    if '--version' in sys.argv:
        print("Onix Scanner v1.0")
        sys.exit(0)
    
    # Get target
    target = clean_url(sys.argv[1])
    
    if not target:
        print(f"{Colors.FAIL}[!] Invalid target URL{Colors.ENDC}")
        sys.exit(1)
    
    # Check internet
    print(f"{Colors.OKBLUE}[*] Checking internet connection...{Colors.ENDC}")
    if not check_internet():
        print(f"{Colors.FAIL}[!] No internet connection detected{Colors.ENDC}")
        sys.exit(1)
    
    print(f"{Colors.OKGREEN}[+] Internet connection OK{Colors.ENDC}\n")
    
    # Initialize scanner
    scanner = Scanner(target)
    
    try:
        # Run scans
        print(f"{Colors.BOLD}Starting scan on {target}...{Colors.ENDC}\n")
        
        if scanner.scan_host_info():
            scanner.scan_http_headers()
            scanner.scan_ssl()
            scanner.scan_robots()
            scanner.scan_ports()
        
        # Generate report
        scanner.generate_report()
        
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Scan interrupted by user{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    main()
