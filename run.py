#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web Penetration Testing Tool
Developed by: Saudi Linux
Email: SaudiLinux7@gmail.com

This is the main execution file that combines all modules.
"""

import os
import sys
import json
import argparse
from datetime import datetime

try:
    import colorama
    from colorama import Fore, Style
except ImportError as e:
    print(f"Error: Missing required dependencies. {e}")
    print("Please run: pip install -r requirements.txt")
    sys.exit(1)

# Initialize colorama
colorama.init(autoreset=True)

# Import our modules
try:
    from metadata_extractor import MetadataExtractor
    from vulnerability_scanner import VulnerabilityScanner
except ImportError as e:
    print(f"Error: Could not import required modules. {e}")
    print("Make sure all files are in the same directory.")
    sys.exit(1)

# Banner
def print_banner():
    banner = f"""
{Fore.RED}██████╗ ███████╗███╗   ██╗████████╗███████╗███████╗████████╗{Style.RESET_ALL}
{Fore.RED}██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝{Style.RESET_ALL}
{Fore.RED}██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ███████╗   ██║   {Style.RESET_ALL}
{Fore.RED}██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ╚════██║   ██║   {Style.RESET_ALL}
{Fore.RED}██║     ███████╗██║ ╚████║   ██║   ███████╗███████║   ██║   {Style.RESET_ALL}
{Fore.RED}╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝   {Style.RESET_ALL}
                                                        
{Fore.CYAN}Web Penetration Testing Tool{Style.RESET_ALL}
{Fore.CYAN}Developed by: Saudi Linux{Style.RESET_ALL}
{Fore.CYAN}Email: SaudiLinux7@gmail.com{Style.RESET_ALL}
{Fore.YELLOW}Version: 1.0{Style.RESET_ALL}
"""
    print(banner)

# Main function
def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description='Web Penetration Testing Tool')
    parser.add_argument('-u', '--url', help='Target URL', required=True)
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-v', '--verbose', help='Verbose output', action='store_true')
    parser.add_argument('--metadata-only', help='Only run metadata extraction', action='store_true')
    parser.add_argument('--vuln-only', help='Only run vulnerability scanning', action='store_true')
    parser.add_argument('-s', '--scan', help='Specify vulnerability scan type (all, xss, sqli, csrf, etc.)', default='all')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'http://' + args.url
    
    print(f"{Fore.CYAN}[*] Target: {args.url}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
    
    results = {}
    
    # Run metadata extraction if not vuln-only
    if not args.vuln_only:
        print(f"\n{Fore.CYAN}[*] Running Metadata Extraction...{Style.RESET_ALL}")
        metadata_extractor = MetadataExtractor(args.url, args.verbose)
        metadata_results = metadata_extractor.extract_all()
        results['metadata'] = metadata_results
        print(f"{Fore.GREEN}[+] Metadata extraction completed!{Style.RESET_ALL}")
    
    # Run vulnerability scanning if not metadata-only
    if not args.metadata_only:
        print(f"\n{Fore.CYAN}[*] Running Vulnerability Scanning...{Style.RESET_ALL}")
        vulnerability_scanner = VulnerabilityScanner(args.url, args.verbose)
        
        if args.scan.lower() == 'all':
            vuln_results = vulnerability_scanner.scan_all()
        elif args.scan.lower() == 'xss':
            vulnerability_scanner.scan_xss()
            vuln_results = {'xss_vulnerabilities': vulnerability_scanner.results.get('xss_vulnerabilities', [])}
        elif args.scan.lower() == 'sqli':
            vulnerability_scanner.scan_sql_injection()
            vuln_results = {'sqli_vulnerabilities': vulnerability_scanner.results.get('sqli_vulnerabilities', [])}
        elif args.scan.lower() == 'csrf':
            vulnerability_scanner.scan_csrf()
            vuln_results = {'csrf_vulnerabilities': vulnerability_scanner.results.get('csrf_vulnerabilities', [])}
        elif args.scan.lower() == 'open_redirect':
            vulnerability_scanner.scan_open_redirects()
            vuln_results = {'open_redirect_vulnerabilities': vulnerability_scanner.results.get('open_redirect_vulnerabilities', [])}
        elif args.scan.lower() == 'misconfig':
            vulnerability_scanner.scan_misconfigurations()
            vuln_results = {'misconfigurations': vulnerability_scanner.results.get('misconfigurations', [])}
        elif args.scan.lower() == 'headers':
            vulnerability_scanner.scan_insecure_headers()
            vuln_results = {'insecure_headers': vulnerability_scanner.results.get('insecure_headers', [])}
        elif args.scan.lower() == 'clickjacking':
            vulnerability_scanner.scan_clickjacking()
            vuln_results = {'clickjacking_vulnerability': vulnerability_scanner.results.get('clickjacking_vulnerability', {})}
        elif args.scan.lower() == 'ssrf':
            vulnerability_scanner.scan_ssrf()
            vuln_results = {'ssrf_vulnerabilities': vulnerability_scanner.results.get('ssrf_vulnerabilities', [])}
        elif args.scan.lower() == 'file_inclusion':
            vulnerability_scanner.scan_file_inclusion()
            vuln_results = {'file_inclusion_vulnerabilities': vulnerability_scanner.results.get('file_inclusion_vulnerabilities', [])}
        elif args.scan.lower() == 'info_disclosure':
            vulnerability_scanner.scan_information_disclosure()
            vuln_results = {'information_disclosure': vulnerability_scanner.results.get('information_disclosure', [])}
        else:
            print(f"{Fore.RED}[!] Unknown scan type: {args.scan}{Style.RESET_ALL}")
            sys.exit(1)
        
        results['vulnerabilities'] = vuln_results
        print(f"{Fore.GREEN}[+] Vulnerability scanning completed!{Style.RESET_ALL}")
    
    # Save results to file if specified
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=4)
            print(f"{Fore.GREEN}[+] Results saved to {args.output}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving results: {e}{Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}[+] Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Thank you for using our Web Penetration Testing Tool!{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] An error occurred: {e}{Style.RESET_ALL}")
        sys.exit(1)