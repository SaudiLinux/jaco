#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Metadata Extractor Module for Web Penetration Testing Tool
Developed by: Saudi Linux
Email: SaudiLinux7@gmail.com

This module is designed to extract metadata from target websites.
"""

import os
import sys
import json
import re
import time
from urllib.parse import urlparse, urljoin
from datetime import datetime

try:
    import requests
    from bs4 import BeautifulSoup
    import colorama
    from colorama import Fore, Style
    import urllib3
    import whois
    import dns.resolver
    from fake_useragent import UserAgent
    import exifread
    from PIL import Image
    from PIL.ExifTags import TAGS
    import io
except ImportError as e:
    print(f"Error: Missing required dependencies. {e}")
    print("Please run: pip install -r requirements.txt")
    sys.exit(1)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
colorama.init(autoreset=True)

# User-Agent rotation
def get_random_user_agent():
    try:
        ua = UserAgent()
        return ua.random
    except:
        # Fallback user agents if fake-useragent fails
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 11.5; rv:90.0) Gecko/20100101 Firefox/90.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_5_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15',
        ]
        return random.choice(user_agents)

# Request wrapper with error handling
def make_request(url, method="GET", data=None, headers=None, timeout=10, allow_redirects=True, verify=False):
    if headers is None:
        headers = {
            'User-Agent': get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
    
    try:
        if method.upper() == "GET":
            response = requests.get(
                url, 
                headers=headers, 
                timeout=timeout, 
                allow_redirects=allow_redirects,
                verify=verify
            )
        elif method.upper() == "POST":
            response = requests.post(
                url, 
                data=data, 
                headers=headers, 
                timeout=timeout, 
                allow_redirects=allow_redirects,
                verify=verify
            )
        elif method.upper() == "HEAD":
            response = requests.head(
                url, 
                headers=headers, 
                timeout=timeout, 
                allow_redirects=allow_redirects,
                verify=verify
            )
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")
            
        return response
    except requests.exceptions.ConnectionError:
        print(f"{Fore.RED}[!] Connection Error: Could not connect to {url}{Style.RESET_ALL}")
    except requests.exceptions.Timeout:
        print(f"{Fore.RED}[!] Timeout Error: Request to {url} timed out{Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Request Error: {e}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
    
    return None

class MetadataExtractor:
    def __init__(self, url, verbose=False):
        self.url = url
        self.verbose = verbose
        self.results = {}
        self.domain = urlparse(url).netloc
    
    def extract_all_metadata(self):
        print(f"\n{Fore.CYAN}[*] Extracting metadata from {self.url}{Style.RESET_ALL}")
        
        self.extract_http_headers()
        self.extract_dns_info()
        self.extract_whois_info()
        self.extract_html_metadata()
        self.extract_server_info()
        self.extract_technologies()
        self.extract_social_media()
        self.extract_email_addresses()
        self.extract_image_metadata()
        self.extract_js_libraries()
        self.extract_subdomains()
        
        return self.results
    
    def extract_http_headers(self):
        print(f"{Fore.YELLOW}[+] Extracting HTTP headers...{Style.RESET_ALL}")
        response = make_request(self.url, method="HEAD")
        
        if response:
            self.results['http_headers'] = dict(response.headers)
            
            # Check for security headers
            security_headers = {
                'Strict-Transport-Security': 'Missing HSTS header',
                'Content-Security-Policy': 'Missing CSP header',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                'X-Frame-Options': 'Missing X-Frame-Options header',
                'X-XSS-Protection': 'Missing X-XSS-Protection header',
                'Referrer-Policy': 'Missing Referrer-Policy header',
                'Permissions-Policy': 'Missing Permissions-Policy header',
            }
            
            missing_headers = []
            for header, message in security_headers.items():
                if header not in response.headers:
                    missing_headers.append(message)
            
            if missing_headers:
                self.results['missing_security_headers'] = missing_headers
                if self.verbose:
                    for msg in missing_headers:
                        print(f"{Fore.RED}[!] {msg}{Style.RESET_ALL}")
    
    def extract_dns_info(self):
        print(f"{Fore.YELLOW}[+] Extracting DNS information...{Style.RESET_ALL}")
        dns_records = {}
        
        try:
            # A records
            try:
                answers = dns.resolver.resolve(self.domain, 'A')
                dns_records['A'] = [answer.address for answer in answers]
            except Exception:
                dns_records['A'] = []
            
            # MX records
            try:
                answers = dns.resolver.resolve(self.domain, 'MX')
                dns_records['MX'] = [str(answer.exchange) for answer in answers]
            except Exception:
                dns_records['MX'] = []
            
            # NS records
            try:
                answers = dns.resolver.resolve(self.domain, 'NS')
                dns_records['NS'] = [str(answer) for answer in answers]
            except Exception:
                dns_records['NS'] = []
            
            # TXT records
            try:
                answers = dns.resolver.resolve(self.domain, 'TXT')
                dns_records['TXT'] = [str(answer) for answer in answers]
            except Exception:
                dns_records['TXT'] = []
                
            # CNAME records
            try:
                answers = dns.resolver.resolve(self.domain, 'CNAME')
                dns_records['CNAME'] = [str(answer) for answer in answers]
            except Exception:
                dns_records['CNAME'] = []
                
            # SOA records
            try:
                answers = dns.resolver.resolve(self.domain, 'SOA')
                dns_records['SOA'] = [str(answer) for answer in answers]
            except Exception:
                dns_records['SOA'] = []
            
            self.results['dns_records'] = dns_records
            
            if self.verbose:
                for record_type, records in dns_records.items():
                    if records:
                        print(f"{Fore.GREEN}[+] {record_type} Records: {', '.join(records)}{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.RED}[!] Error extracting DNS information: {e}{Style.RESET_ALL}")
    
    def extract_whois_info(self):
        print(f"{Fore.YELLOW}[+] Extracting WHOIS information...{Style.RESET_ALL}")
        try:
            whois_info = whois.whois(self.domain)
            
            # Extract relevant WHOIS data
            relevant_whois = {
                'registrar': whois_info.registrar,
                'creation_date': str(whois_info.creation_date),
                'expiration_date': str(whois_info.expiration_date),
                'name_servers': whois_info.name_servers,
                'status': whois_info.status,
                'emails': whois_info.emails,
                'org': whois_info.org,
                'country': whois_info.country,
            }
            
            self.results['whois_info'] = relevant_whois
            
            if self.verbose:
                print(f"{Fore.GREEN}[+] Registrar: {whois_info.registrar}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] Organization: {whois_info.org}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] Creation Date: {whois_info.creation_date}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] Expiration Date: {whois_info.expiration_date}{Style.RESET_ALL}")
                if whois_info.emails:
                    print(f"{Fore.GREEN}[+] Contact Emails: {whois_info.emails}{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.RED}[!] Error extracting WHOIS information: {e}{Style.RESET_ALL}")
    
    def extract_html_metadata(self):
        print(f"{Fore.YELLOW}[+] Extracting HTML metadata...{Style.RESET_ALL}")
        response = make_request(self.url)
        
        if response:
            try:
                soup = BeautifulSoup(response.text, 'html.parser')
                meta_tags = {}
                
                # Extract meta tags
                for meta in soup.find_all('meta'):
                    name = meta.get('name') or meta.get('property')
                    content = meta.get('content')
                    
                    if name and content:
                        meta_tags[name] = content
                
                # Extract title
                title = soup.find('title')
                if title:
                    meta_tags['title'] = title.text
                
                # Extract generator info
                generator = soup.find('meta', attrs={'name': 'generator'})
                if generator:
                    self.results['cms'] = generator.get('content')
                
                # Extract links
                links = []
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if href.startswith('http') or href.startswith('https'):
                        links.append(href)
                    else:
                        # Convert relative URLs to absolute
                        absolute_url = urljoin(self.url, href)
                        links.append(absolute_url)
                
                # Extract scripts
                scripts = [script.get('src') for script in soup.find_all('script', src=True)]
                
                # Extract comments
                comments = []
                for comment in soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--')):
                    comments.append(comment.strip())
                
                self.results['meta_tags'] = meta_tags
                self.results['links'] = links[:50]  # Limit to 50 links
                self.results['scripts'] = scripts
                self.results['comments'] = comments
                
                if self.verbose:
                    print(f"{Fore.GREEN}[+] Found {len(meta_tags)} meta tags{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Found {len(links)} links{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Found {len(scripts)} scripts{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Found {len(comments)} comments{Style.RESET_ALL}")
            
            except Exception as e:
                print(f"{Fore.RED}[!] Error parsing HTML: {e}{Style.RESET_ALL}")
    
    def extract_server_info(self):
        print(f"{Fore.YELLOW}[+] Extracting server information...{Style.RESET_ALL}")
        response = make_request(self.url, method="HEAD")
        
        if response and 'Server' in response.headers:
            server = response.headers['Server']
            self.results['server'] = server
            
            if self.verbose:
                print(f"{Fore.GREEN}[+] Server: {server}{Style.RESET_ALL}")
                
        # Check for X-Powered-By header
        if response and 'X-Powered-By' in response.headers:
            powered_by = response.headers['X-Powered-By']
            self.results['powered_by'] = powered_by
            
            if self.verbose:
                print(f"{Fore.GREEN}[+] Powered By: {powered_by}{Style.RESET_ALL}")
    
    def extract_technologies(self):
        print(f"{Fore.YELLOW}[+] Detecting technologies...{Style.RESET_ALL}")
        response = make_request(self.url)
        
        if not response:
            return
        
        technologies = []
        
        # Check HTML content
        html_content = response.text.lower()
        
        # Check for common CMS
        cms_patterns = {
            'wordpress': ['wp-content', 'wp-includes', 'wordpress'],
            'joomla': ['joomla', 'com_content', 'com_users'],
            'drupal': ['drupal', 'sites/all', 'sites/default'],
            'magento': ['magento', 'skin/frontend', 'mage/'],
            'shopify': ['cdn.shopify.com', 'shopify.com'],
            'wix': ['wix.com', 'wixsite.com'],
            'squarespace': ['squarespace.com', 'static.squarespace.com'],
            'webflow': ['webflow.com', 'assets.website-files.com'],
        }
        
        for cms, patterns in cms_patterns.items():
            for pattern in patterns:
                if pattern in html_content:
                    technologies.append({
                        'name': cms.capitalize(),
                        'type': 'CMS',
                        'confidence': 'High'
                    })
                    break
        
        # Check for JavaScript frameworks
        js_frameworks = {
            'jquery': ['jquery'],
            'react': ['react', 'reactjs', 'react.js', 'react-dom'],
            'angular': ['angular', 'ng-app', 'ng-controller'],
            'vue': ['vue', 'vue.js', 'vuejs'],
            'bootstrap': ['bootstrap'],
            'tailwind': ['tailwind', 'tailwindcss'],
            'gsap': ['gsap', 'tweenmax'],
            'three.js': ['three.js', 'threejs'],
        }
        
        for framework, patterns in js_frameworks.items():
            for pattern in patterns:
                if pattern in html_content:
                    technologies.append({
                        'name': framework.capitalize(),
                        'type': 'JavaScript Framework',
                        'confidence': 'Medium'
                    })
                    break
        
        # Check for web servers from headers
        if 'Server' in response.headers:
            server = response.headers['Server']
            server_patterns = {
                'apache': ['apache'],
                'nginx': ['nginx'],
                'iis': ['iis', 'microsoft-iis'],
                'cloudflare': ['cloudflare'],
                'litespeed': ['litespeed'],
                'openresty': ['openresty'],
            }
            
            for server_name, patterns in server_patterns.items():
                for pattern in patterns:
                    if pattern.lower() in server.lower():
                        technologies.append({
                            'name': server_name.capitalize(),
                            'type': 'Web Server',
                            'confidence': 'High'
                        })
                        break
        
        # Check for analytics and tracking tools
        analytics_patterns = {
            'google analytics': ['google-analytics.com', 'ga.js', 'analytics.js', 'gtag'],
            'google tag manager': ['googletagmanager.com', 'gtm.js'],
            'facebook pixel': ['connect.facebook.net', 'fbevents.js'],
            'hotjar': ['hotjar.com', 'hotjar'],
            'matomo': ['matomo.js', 'piwik.js'],
            'mixpanel': ['mixpanel.com', 'mixpanel'],
            'segment': ['segment.com', 'segment'],
        }
        
        for tool, patterns in analytics_patterns.items():
            for pattern in patterns:
                if pattern in html_content:
                    technologies.append({
                        'name': tool.capitalize(),
                        'type': 'Analytics',
                        'confidence': 'Medium'
                    })
                    break
        
        # Check for programming languages
        lang_patterns = {
            'php': ['.php', 'php'],
            'asp.net': ['.aspx', '.asp', 'asp.net'],
            'java': ['.jsp', 'java', 'jsessionid'],
            'python': ['python', 'django', 'flask'],
            'ruby': ['ruby', 'rails'],
            'node.js': ['node', 'express'],
        }
        
        for lang, patterns in lang_patterns.items():
            for pattern in patterns:
                if pattern in html_content or pattern in str(response.headers).lower():
                    technologies.append({
                        'name': lang.capitalize(),
                        'type': 'Programming Language',
                        'confidence': 'Medium'
                    })
                    break
        
        # Remove duplicates
        unique_techs = []
        tech_names = set()
        
        for tech in technologies:
            if tech['name'].lower() not in tech_names:
                tech_names.add(tech['name'].lower())
                unique_techs.append(tech)
        
        self.results['technologies'] = unique_techs
        
        if self.verbose and unique_techs:
            print(f"{Fore.GREEN}[+] Detected technologies:{Style.RESET_ALL}")
            for tech in unique_techs:
                print(f"{Fore.GREEN}   - {tech['name']} ({tech['type']}){Style.RESET_ALL}")
    
    def extract_social_media(self):
        print(f"{Fore.YELLOW}[+] Extracting social media links...{Style.RESET_ALL}")
        response = make_request(self.url)
        
        if not response:
            return
        
        social_media = {
            'facebook': [],
            'twitter': [],
            'instagram': [],
            'linkedin': [],
            'youtube': [],
            'github': [],
            'pinterest': [],
            'tiktok': [],
        }
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Define social media patterns
        social_patterns = {
            'facebook': ['facebook.com', 'fb.com'],
            'twitter': ['twitter.com', 'x.com'],
            'instagram': ['instagram.com'],
            'linkedin': ['linkedin.com'],
            'youtube': ['youtube.com', 'youtu.be'],
            'github': ['github.com'],
            'pinterest': ['pinterest.com'],
            'tiktok': ['tiktok.com'],
        }
        
        # Extract links
        for link in soup.find_all('a', href=True):
            href = link['href'].lower()
            
            for platform, patterns in social_patterns.items():
                for pattern in patterns:
                    if pattern in href and href not in social_media[platform]:
                        social_media[platform].append(href)
        
        # Filter out empty lists
        social_media = {k: v for k, v in social_media.items() if v}
        
        if social_media:
            self.results['social_media'] = social_media
            
            if self.verbose:
                print(f"{Fore.GREEN}[+] Found social media profiles:{Style.RESET_ALL}")
                for platform, links in social_media.items():
                    if links:
                        print(f"{Fore.GREEN}   - {platform.capitalize()}: {links[0]}{Style.RESET_ALL}")
    
    def extract_email_addresses(self):
        print(f"{Fore.YELLOW}[+] Extracting email addresses...{Style.RESET_ALL}")
        response = make_request(self.url)
        
        if not response:
            return
        
        # Regular expression for email addresses
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, response.text)
        
        # Remove duplicates
        unique_emails = list(set(emails))
        
        if unique_emails:
            self.results['email_addresses'] = unique_emails
            
            if self.verbose:
                print(f"{Fore.GREEN}[+] Found {len(unique_emails)} email addresses{Style.RESET_ALL}")
                for email in unique_emails[:5]:  # Show only first 5 emails
                    print(f"{Fore.GREEN}   - {email}{Style.RESET_ALL}")
                if len(unique_emails) > 5:
                    print(f"{Fore.GREEN}   - ... and {len(unique_emails) - 5} more{Style.RESET_ALL}")
    
    def extract_image_metadata(self):
        print(f"{Fore.YELLOW}[+] Extracting image metadata...{Style.RESET_ALL}")
        response = make_request(self.url)
        
        if not response:
            return
        
        soup = BeautifulSoup(response.text, 'html.parser')
        images = soup.find_all('img', src=True)
        
        image_metadata = []
        
        for img in images[:10]:  # Limit to first 10 images to avoid excessive requests
            src = img['src']
            
            # Convert relative URLs to absolute
            if not src.startswith(('http://', 'https://')):
                src = urljoin(self.url, src)
            
            # Skip data URIs
            if src.startswith('data:'):
                continue
            
            try:
                img_response = make_request(src)
                if img_response and img_response.status_code == 200:
                    # Extract basic image info
                    img_info = {
                        'url': src,
                        'alt': img.get('alt', ''),
                        'size': len(img_response.content),
                        'content_type': img_response.headers.get('Content-Type', ''),
                    }
                    
                    # Try to extract EXIF data
                    try:
                        image_data = io.BytesIO(img_response.content)
                        img_exif = Image.open(image_data)
                        
                        exif_data = {}
                        if hasattr(img_exif, '_getexif') and img_exif._getexif():
                            for tag, value in img_exif._getexif().items():
                                if tag in TAGS:
                                    exif_data[TAGS[tag]] = str(value)
                        
                        if exif_data:
                            img_info['exif'] = exif_data
                    except Exception:
                        pass
                    
                    image_metadata.append(img_info)
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error extracting metadata from image {src}: {e}{Style.RESET_ALL}")
        
        if image_metadata:
            self.results['image_metadata'] = image_metadata
            
            if self.verbose:
                print(f"{Fore.GREEN}[+] Extracted metadata from {len(image_metadata)} images{Style.RESET_ALL}")
                for img in image_metadata:
                    if 'exif' in img and img['exif']:
                        print(f"{Fore.GREEN}   - {img['url']} contains EXIF data{Style.RESET_ALL}")
    
    def extract_js_libraries(self):
        print(f"{Fore.YELLOW}[+] Extracting JavaScript libraries...{Style.RESET_ALL}")
        response = make_request(self.url)
        
        if not response:
            return
        
        soup = BeautifulSoup(response.text, 'html.parser')
        scripts = soup.find_all('script', src=True)
        
        js_libraries = []
        
        for script in scripts:
            src = script['src']
            
            # Convert relative URLs to absolute
            if not src.startswith(('http://', 'https://')):
                src = urljoin(self.url, src)
            
            # Extract library name from URL
            library_name = src.split('/')[-1]
            
            # Try to identify common libraries
            library_info = {
                'url': src,
                'filename': library_name,
            }
            
            # Check for version information
            version_match = re.search(r'[\.-](\d+(?:\.\d+)+)', library_name)
            if version_match:
                library_info['version'] = version_match.group(1)
            
            js_libraries.append(library_info)
        
        if js_libraries:
            self.results['js_libraries'] = js_libraries
            
            if self.verbose:
                print(f"{Fore.GREEN}[+] Found {len(js_libraries)} JavaScript libraries{Style.RESET_ALL}")
                for lib in js_libraries[:5]:  # Show only first 5 libraries
                    version_info = f" (v{lib['version']})" if 'version' in lib else ""
                    print(f"{Fore.GREEN}   - {lib['filename']}{version_info}{Style.RESET_ALL}")
                if len(js_libraries) > 5:
                    print(f"{Fore.GREEN}   - ... and {len(js_libraries) - 5} more{Style.RESET_ALL}")
    
    def extract_subdomains(self):
        print(f"{Fore.YELLOW}[+] Extracting potential subdomains...{Style.RESET_ALL}")
        
        # Extract base domain (e.g., example.com from www.example.com)
        domain_parts = self.domain.split('.')
        if len(domain_parts) > 2:
            base_domain = '.'.join(domain_parts[-2:])
        else:
            base_domain = self.domain
        
        subdomains = set()
        
        # Try to get subdomains from DNS
        try:
            # Check if we have NS records
            if 'dns_records' in self.results and 'NS' in self.results['dns_records']:
                # For each nameserver, try a zone transfer (AXFR)
                for ns in self.results['dns_records']['NS']:
                    try:
                        axfr = dns.query.xfr(ns, base_domain, timeout=5, lifetime=10)
                        for record in axfr:
                            for name in record.answer:
                                subdomain = str(name.name)
                                if subdomain.endswith(base_domain) and subdomain != base_domain:
                                    subdomains.add(subdomain)
                    except Exception:
                        # Zone transfers are usually disabled, so this is expected to fail
                        pass
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error during zone transfer attempt: {e}{Style.RESET_ALL}")
        
        # Extract subdomains from links in the page
        response = make_request(self.url)
        if response:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract from links
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith(('http://', 'https://')):
                    try:
                        link_domain = urlparse(href).netloc
                        if link_domain.endswith(base_domain) and link_domain != base_domain and link_domain != self.domain:
                            subdomains.add(link_domain)
                    except Exception:
                        pass
        
        # Convert set to list for JSON serialization
        if subdomains:
            self.results['subdomains'] = list(subdomains)
            
            if self.verbose:
                print(f"{Fore.GREEN}[+] Found {len(subdomains)} potential subdomains{Style.RESET_ALL}")
                for subdomain in list(subdomains)[:5]:  # Show only first 5 subdomains
                    print(f"{Fore.GREEN}   - {subdomain}{Style.RESET_ALL}")
                if len(subdomains) > 5:
                    print(f"{Fore.GREEN}   - ... and {len(subdomains) - 5} more{Style.RESET_ALL}")

# Main function for standalone usage
def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Metadata Extractor for Web Penetration Testing')
    parser.add_argument('-u', '--url', help='Target URL', required=True)
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-v', '--verbose', help='Verbose output', action='store_true')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'http://' + args.url
    
    print(f"{Fore.CYAN}[*] Target: {args.url}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Extraction started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
    
    # Extract metadata
    metadata_extractor = MetadataExtractor(args.url, args.verbose)
    results = metadata_extractor.extract_all_metadata()
    
    # Save results to file if specified
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=4)
            print(f"{Fore.GREEN}[+] Results saved to {args.output}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving results: {e}{Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}[+] Metadata extraction completed!{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Extraction interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] An error occurred: {e}{Style.RESET_ALL}")
        sys.exit(1)