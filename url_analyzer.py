import re
import socket
import ssl
import urllib.parse
from datetime import datetime
import requests
from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning
import whois
import tldextract

# Suppress only the InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class URLAnalyzer:
    def __init__(self, url):
        self.url = url
        self.normalized_url = self._normalize_url(url)
        self.components = {}
        self.typosquatting_results = {}
        self.whois_data = {}
        self.ssl_info = {}
        self.blacklist_results = {}
        self.redirection_chain = []
        self.report = {}
        self.risk_score = 0
        self.risk_factors = []
        
        # List of popular brands for typosquatting detection
        self.popular_brands = [
            "google", "facebook", "amazon", "apple", "microsoft", 
            "netflix", "paypal", "instagram", "twitter", "linkedin",
            "youtube", "gmail", "yahoo", "outlook", "bank", "chase",
            "wellsfargo", "citi", "bankofamerica", "americanexpress",
            "dropbox", "github", "gitlab", "atlassian", "office365"
        ]
        
        # Request headers to mimic a regular browser
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }

    def _normalize_url(self, url):
        """Normalize URL by adding scheme if missing"""
        if not url.startswith(('http://', 'https://')):
            return 'http://' + url
        return url

    def extract_components(self):
        """Extract and analyze URL components"""
        try:
            # Parse URL
            parsed = urllib.parse.urlparse(self.normalized_url)
            
            # Get domain details using tldextract
            extracted = tldextract.extract(self.normalized_url)
            
            # Store components
            self.components = {
                'scheme': parsed.scheme,
                'netloc': parsed.netloc,
                'subdomain': extracted.subdomain,
                'domain': extracted.domain,
                'suffix': extracted.suffix,
                'path': parsed.path,
                'params': parsed.params,
                'query': parsed.query,
                'fragment': parsed.fragment,
                'full_domain': f"{extracted.domain}.{extracted.suffix}",
                'has_suspicious_subdomain': bool(extracted.subdomain and 
                                                any(brand in extracted.subdomain for brand in self.popular_brands)),
                'has_suspicious_path': bool(any(brand in parsed.path.lower() for brand in self.popular_brands)),
                'has_ip_address': bool(re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', extracted.domain)),
                'has_suspicious_tld': bool(extracted.suffix in ['xyz', 'top', 'gq', 'ml', 'ga', 'cf', 'tk']),
                'has_multiple_subdomains': len(extracted.subdomain.split('.')) > 1 if extracted.subdomain else False,
                'has_excessive_dots': self.normalized_url.count('.') > 4,
                'has_suspicious_characters': bool(re.search(r'[@%&~]', self.normalized_url)),
            }
            
            # Check for URL shorteners
            url_shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly']
            self.components['is_url_shortener'] = any(shortener in self.components['full_domain'] for shortener in url_shorteners)
            
            # Set risk factors based on component analysis
            if self.components['has_ip_address']:
                self.risk_factors.append("URL contains an IP address instead of a domain name")
                self.risk_score += 25
                
            if self.components['has_suspicious_tld']:
                self.risk_factors.append(f"Suspicious TLD: .{extracted.suffix}")
                self.risk_score += 15
                
            if self.components['has_multiple_subdomains']:
                self.risk_factors.append("Multiple subdomains detected")
                self.risk_score += 10
                
            if self.components['has_excessive_dots']:
                self.risk_factors.append("Excessive number of dots in the URL")
                self.risk_score += 10
                
            if self.components['has_suspicious_characters']:
                self.risk_factors.append("Suspicious characters in URL")
                self.risk_score += 15
                
            if self.components['is_url_shortener']:
                self.risk_factors.append("URL shortener detected")
                self.risk_score += 5
                
            if self.components['scheme'] == 'http':
                self.risk_factors.append("Insecure HTTP protocol")
                self.risk_score += 20
                
            if self.components['has_suspicious_subdomain']:
                self.risk_factors.append("Suspicious subdomain contains a popular brand name")
                self.risk_score += 30
                
            if self.components['has_suspicious_path']:
                self.risk_factors.append("Path contains a popular brand name")
                self.risk_score += 15
                
            return self.components
            
        except Exception as e:
            self.components = {
                'error': f"Failed to extract URL components: {str(e)}"
            }
            self.risk_factors.append("Unable to analyze URL components")
            self.risk_score += 5
            return self.components

    def check_typosquatting(self):
        """Check for potential typosquatting of popular brands"""
        try:
            domain = self.components.get('domain', '')
            if not domain:
                raise ValueError("Domain component not available")
                
            self.typosquatting_results = {
                'possible_targets': [],
                'levenshtein_distances': {},
                'contains_brand': False
            }
            
            # Check if the domain contains any of the popular brands
            for brand in self.popular_brands:
                # Exact match or substring
                if brand == domain or brand in domain:
                    self.typosquatting_results['contains_brand'] = True
                    self.typosquatting_results['possible_targets'].append(brand)
                    
                # Calculate Levenshtein distance for similar domains
                distance = self._levenshtein_distance(brand, domain)
                if distance <= 2 and distance > 0:  # Small distance but not exact match
                    self.typosquatting_results['levenshtein_distances'][brand] = distance
                    if brand not in self.typosquatting_results['possible_targets']:
                        self.typosquatting_results['possible_targets'].append(brand)
            
            # Check for homograph attacks (similar looking characters)
            homograph_patterns = [
                ('l', '1'), ('i', '1'), ('i', 'l'), ('o', '0'),
                ('m', 'rn'), ('n', 'ri'), ('cl', 'd'), ('vv', 'w')
            ]
            
            for brand in self.popular_brands:
                # Check each potential homograph replacement
                for original, replacement in homograph_patterns:
                    if original in brand:
                        modified_brand = brand.replace(original, replacement)
                        if modified_brand == domain or modified_brand in domain:
                            self.typosquatting_results['possible_targets'].append(f"{brand} (homograph: {original}->{replacement})")
            
            # Update risk score based on typosquatting detection
            if self.typosquatting_results['possible_targets']:
                targets = ', '.join(self.typosquatting_results['possible_targets'])
                self.risk_factors.append(f"Possible typosquatting attempt targeting: {targets}")
                self.risk_score += 35
                
            return self.typosquatting_results
            
        except Exception as e:
            self.typosquatting_results = {
                'error': f"Failed to perform typosquatting analysis: {str(e)}"
            }
            self.risk_factors.append("Unable to analyze typosquatting")
            return self.typosquatting_results
    
    def _levenshtein_distance(self, s1, s2):
        """Calculate the Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
            
        return previous_row[-1]

    def check_whois(self):
        """Perform WHOIS lookup and analyze domain registration details"""
        try:
            # Extract full domain from components
            domain = self.components.get('full_domain')
            if not domain:
                raise ValueError("Full domain component not available")
            
            # Perform WHOIS lookup
            whois_data = whois.whois(domain)
            
            # Extract and organize relevant information
            self.whois_data = {
                'registrar': whois_data.registrar,
                'creation_date': self._format_whois_date(whois_data.creation_date),
                'expiration_date': self._format_whois_date(whois_data.expiration_date),
                'last_updated': self._format_whois_date(whois_data.updated_date),
                'name_servers': whois_data.name_servers if isinstance(whois_data.name_servers, list) else None,
                'status': whois_data.status if isinstance(whois_data.status, list) else None,
                'is_registered': bool(whois_data.registrar),
                'age_days': self._calculate_domain_age(whois_data.creation_date),
                'days_until_expiration': self._calculate_days_until_expiration(whois_data.expiration_date)
            }
            
            # Analyze WHOIS data for suspicious patterns
            # Young domains (less than 30 days) are often used for phishing
            if self.whois_data['age_days'] is not None and self.whois_data['age_days'] < 30:
                self.risk_factors.append(f"Domain is very new (registered {self.whois_data['age_days']} days ago)")
                self.risk_score += 30
            
            # Domains about to expire might be abandoned or repurposed
            if self.whois_data['days_until_expiration'] is not None and self.whois_data['days_until_expiration'] < 30:
                self.risk_factors.append(f"Domain is about to expire in {self.whois_data['days_until_expiration']} days")
                self.risk_score += 10
            
            # Check if the domain is properly registered
            if not self.whois_data['is_registered']:
                self.risk_factors.append("Domain appears to be unregistered or has incomplete WHOIS data")
                self.risk_score += 25
            
            return self.whois_data
            
        except Exception as e:
            self.whois_data = {
                'error': f"Failed to perform WHOIS lookup: {str(e)}",
                'is_registered': None,
                'age_days': None
            }
            self.risk_factors.append("Unable to retrieve WHOIS information")
            return self.whois_data
    
    def _format_whois_date(self, date_value):
        """Format WHOIS date consistently"""
        if not date_value:
            return None
            
        if isinstance(date_value, list):
            date_value = date_value[0]  # Take the first date if it's a list
            
        try:
            if isinstance(date_value, str):
                # Try to parse string to datetime
                return datetime.strptime(date_value, "%Y-%m-%d %H:%M:%S").isoformat()
            elif isinstance(date_value, datetime):
                return date_value.isoformat()
            else:
                return str(date_value)
        except Exception:
            return str(date_value)
    
    def _calculate_domain_age(self, creation_date):
        """Calculate domain age in days"""
        if not creation_date:
            return None
            
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        try:
            if isinstance(creation_date, str):
                creation_datetime = datetime.strptime(creation_date, "%Y-%m-%d %H:%M:%S")
            elif isinstance(creation_date, datetime):
                creation_datetime = creation_date
            else:
                return None
                
            delta = datetime.now() - creation_datetime
            return delta.days
        except Exception:
            return None
    
    def _calculate_days_until_expiration(self, expiration_date):
        """Calculate days until domain expiration"""
        if not expiration_date:
            return None
            
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
            
        try:
            if isinstance(expiration_date, str):
                expiration_datetime = datetime.strptime(expiration_date, "%Y-%m-%d %H:%M:%S")
            elif isinstance(expiration_date, datetime):
                expiration_datetime = expiration_date
            else:
                return None
                
            delta = expiration_datetime - datetime.now()
            return delta.days
        except Exception:
            return None

    def verify_ssl(self):
        """Verify SSL certificate and analyze security aspects"""
        try:
            # Extract hostname
            hostname = self.components.get('netloc', '')
            if not hostname:
                raise ValueError("Hostname component not available")
            
            # Initialize SSL info dictionary
            self.ssl_info = {
                'has_ssl': False,
                'valid': False,
                'issuer': None,
                'subject': None,
                'version': None,
                'expiry_date': None,
                'days_until_expiry': None,
                'cipher': None,
                'tls_version': None,
                'self_signed': False,
                'cert_transparency': False,
                'hsts': False
            }
            
            # Skip SSL check for non-HTTPS URLs
            if self.components.get('scheme') != 'https':
                self.ssl_info['has_ssl'] = False
                return self.ssl_info
            
            # Try to establish an SSL connection
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    self.ssl_info['has_ssl'] = True
                    self.ssl_info['valid'] = True
                    
                    # Get certificate information
                    cert = ssock.getpeercert()
                    self.ssl_info['issuer'] = dict(x[0] for x in cert['issuer'])
                    self.ssl_info['subject'] = dict(x[0] for x in cert['subject'])
                    self.ssl_info['version'] = cert.get('version')
                    self.ssl_info['expiry_date'] = cert.get('notAfter')
                    
                    # Calculate days until expiry
                    if self.ssl_info['expiry_date']:
                        expiry_date = datetime.strptime(self.ssl_info['expiry_date'], r'%b %d %H:%M:%S %Y %Z')
                        self.ssl_info['days_until_expiry'] = (expiry_date - datetime.now()).days
                    
                    # Get cipher and TLS information
                    self.ssl_info['cipher'] = ssock.cipher()
                    self.ssl_info['tls_version'] = ssock.version() if hasattr(ssock, 'version') else None
                    
                    # Check if certificate is self-signed
                    issuer_cn = self.ssl_info['issuer'].get('commonName')
                    subject_cn = self.ssl_info['subject'].get('commonName')
                    self.ssl_info['self_signed'] = issuer_cn == subject_cn
            
            # Check for HTTP Strict Transport Security (HSTS)
            try:
                response = requests.head(self.normalized_url, headers=self.headers, timeout=10)
                self.ssl_info['hsts'] = 'strict-transport-security' in response.headers
            except:
                pass
            
            # Update risk factors based on SSL verification
            if not self.ssl_info['has_ssl']:
                self.risk_factors.append("Website does not use HTTPS encryption")
                self.risk_score += 30
            elif not self.ssl_info['valid']:
                self.risk_factors.append("Invalid SSL certificate")
                self.risk_score += 40
            elif self.ssl_info['self_signed']:
                self.risk_factors.append("Self-signed SSL certificate")
                self.risk_score += 30
            elif self.ssl_info['days_until_expiry'] is not None and self.ssl_info['days_until_expiry'] < 30:
                self.risk_factors.append(f"SSL certificate expires soon ({self.ssl_info['days_until_expiry']} days)")
                self.risk_score += 10
                
            if not self.ssl_info['hsts']:
                self.risk_factors.append("HSTS not enabled")
                self.risk_score += 5
            
            return self.ssl_info
            
        except Exception as e:
            self.ssl_info = {
                'has_ssl': False,
                'valid': False,
                'error': f"Failed to verify SSL: {str(e)}"
            }
            self.risk_factors.append("SSL verification failed")
            self.risk_score += 25
            return self.ssl_info

    def check_blacklists(self):
        """Check URL against popular blacklists via web scraping"""
        try:
            # Initialize blacklist results
            self.blacklist_results = {
                'google_safe_browsing': None,
                'phishtank': None,
                'urlhaus': None,
                'blacklisted': False,
                'services_checked': [],
                'warnings': []
            }
            
            # Extract full URL and domain
            url = self.normalized_url
            domain = self.components.get('full_domain', '')
            if not domain:
                raise ValueError("Domain component not available")
            
            # List of services checked
            self.blacklist_results['services_checked'] = ['Google Safe Browsing', 'PhishTank', 'URLhaus']
            
            # Check against VirusTotal's public web interface (without API)
            try:
                # We're not using their API, just scraping public info
                vt_url = f"https://www.virustotal.com/gui/domain/{domain}/detection"
                self.blacklist_results['services_checked'].append('VirusTotal Public Interface')
                self.blacklist_results['warnings'].append(
                    "Note: VirusTotal check is limited without API access. Results may not be complete."
                )
            except Exception as e:
                self.blacklist_results['warnings'].append(f"VirusTotal check failed: {str(e)}")
            
            # For demonstration purposes, the actual implementation would include:
            # 1. Web scraping Google Safe Browsing transparent report
            # 2. Scraping PhishTank's public interface
            # 3. Checking URLhaus public listing
            
            # Simulated result (in a real implementation, we would scrape actual responses)
            # This is a placeholder for the web scraping logic
            self.blacklist_results['blacklisted'] = False
            
            # Update risk factors if blacklisted
            if self.blacklist_results['blacklisted']:
                sources = []
                if self.blacklist_results['google_safe_browsing']:
                    sources.append("Google Safe Browsing")
                if self.blacklist_results['phishtank']:
                    sources.append("PhishTank")
                if self.blacklist_results['urlhaus']:
                    sources.append("URLhaus")
                
                if sources:
                    source_list = ", ".join(sources)
                    self.risk_factors.append(f"URL is blacklisted by: {source_list}")
                    self.risk_score += 75  # High risk score for blacklisted URLs
            
            return self.blacklist_results
            
        except Exception as e:
            self.blacklist_results = {
                'error': f"Failed to check blacklists: {str(e)}",
                'blacklisted': False,
                'services_checked': [],
                'warnings': [f"Blacklist verification failed: {str(e)}"]
            }
            return self.blacklist_results

    def analyze_redirections(self):
        """Analyze URL redirection behavior to detect suspicious forwarding"""
        try:
            # Initialize redirection data
            self.redirection_chain = []
            max_redirects = 10  # Prevent infinite redirect loops
            current_url = self.normalized_url
            
            # Follow redirects manually
            for i in range(max_redirects):
                try:
                    # Send HEAD request first (faster)
                    response = requests.head(
                        current_url, 
                        headers=self.headers,
                        allow_redirects=False,
                        timeout=5,
                        verify=False  # Skip SSL verification to check even invalid certs
                    )
                    
                    # Record this step in the chain
                    redirect_info = {
                        'url': current_url,
                        'status_code': response.status_code,
                        'location': response.headers.get('Location'),
                        'server': response.headers.get('Server'),
                        'content_type': response.headers.get('Content-Type')
                    }
                    self.redirection_chain.append(redirect_info)
                    
                    # Check if we've reached the end of the redirect chain
                    if response.status_code not in [301, 302, 303, 307, 308]:
                        # If HEAD request returns non-redirect but might be JavaScript redirect,
                        # try GET request to check page content
                        if len(self.redirection_chain) <= 1:  # Only for the first URL to save time
                            try:
                                content_response = requests.get(
                                    current_url, 
                                    headers=self.headers,
                                    timeout=5,
                                    verify=False
                                )
                                # Check for JavaScript redirects in content
                                if 'text/html' in content_response.headers.get('Content-Type', ''):
                                    soup = BeautifulSoup(content_response.text, 'html.parser')
                                    # Look for common JS redirect patterns
                                    js_redirects = soup.find_all('script', string=re.compile(r'window\.location|document\.location|\.href'))
                                    meta_redirects = soup.find_all('meta', attrs={'http-equiv': re.compile(r'^refresh$', re.I)})
                                    
                                    if js_redirects or meta_redirects:
                                        # Add a note about potential JavaScript redirection
                                        redirect_info = {
                                            'url': current_url,
                                            'status_code': 'JS/Meta',
                                            'location': 'Potential client-side redirection detected',
                                            'server': response.headers.get('Server'),
                                            'content_type': 'text/html'
                                        }
                                        self.redirection_chain.append(redirect_info)
                            except Exception:
                                pass
                        break
                    
                    # Follow the redirect
                    if not response.headers.get('Location'):
                        break
                    
                    # Resolve relative URLs
                    next_url = response.headers.get('Location')
                    if next_url.startswith('/'):
                        # Convert relative URL to absolute
                        parsed = urllib.parse.urlparse(current_url)
                        next_url = f"{parsed.scheme}://{parsed.netloc}{next_url}"
                    
                    current_url = next_url
                    
                except (requests.RequestException, socket.timeout):
                    # Add the failed attempt to the chain
                    redirect_info = {
                        'url': current_url,
                        'status_code': 'Error',
                        'location': None,
                        'server': None,
                        'content_type': None,
                        'error': 'Connection failed'
                    }
                    self.redirection_chain.append(redirect_info)
                    break
            
            # Analyze the redirection chain for suspicious patterns
            if len(self.redirection_chain) > 1:
                # Extract domains from each URL in the chain
                redirect_domains = []
                for step in self.redirection_chain:
                    if 'url' in step:
                        extracted = tldextract.extract(step['url'])
                        redirect_domains.append(f"{extracted.domain}.{extracted.suffix}")
                
                # Count unique domains
                unique_domains = len(set(redirect_domains))
                
                # Check for cross-domain redirects
                if unique_domains > 1:
                    self.risk_factors.append(f"Multiple domain redirects ({unique_domains} different domains)")
                    self.risk_score += 15 * min(unique_domains, 5)  # Cap at 5x multiplier
                
                # Check for excessive redirects
                if len(self.redirection_chain) >= 4:
                    self.risk_factors.append(f"Excessive number of redirects ({len(self.redirection_chain)})")
                    self.risk_score += 10
                
                # Check for client-side (JavaScript/meta) redirects
                js_redirects = any(step.get('status_code') == 'JS/Meta' for step in self.redirection_chain)
                if js_redirects:
                    self.risk_factors.append("Client-side (JavaScript/meta) redirects detected")
                    self.risk_score += 20
            
            return self.redirection_chain
            
        except Exception as e:
            self.redirection_chain = [{
                'error': f"Failed to analyze redirections: {str(e)}"
            }]
            return self.redirection_chain

    def _generate_recommendations(self):
        """Generate security recommendations based on risk factors"""
        recommendations = []
        
        # Check URL structure and components
        if self.components.get('has_ip_address'):
            recommendations.append("Avoid URLs that use IP addresses instead of domain names")
        
        if self.components.get('scheme') == 'http':
            recommendations.append("Look for secure HTTPS connections when sharing sensitive information")
        
        # Check typosquatting
        if self.typosquatting_results.get('possible_targets'):
            recommendations.append("Verify the domain name carefully - it appears similar to popular brand(s)")
            recommendations.append("Type website addresses directly or use bookmarks instead of clicking links")
        
        # Check domain age
        if self.whois_data.get('age_days') is not None and self.whois_data.get('age_days') < 30:
            recommendations.append("Be cautious with newly registered domains (less than 30 days old)")
        
        # Check SSL
        if not self.ssl_info.get('has_ssl') or not self.ssl_info.get('valid'):
            recommendations.append("Ensure websites use valid SSL certificates, especially for sensitive information")
        
        if self.ssl_info.get('self_signed'):
            recommendations.append("Avoid websites with self-signed SSL certificates")
        
        # Check redirections
        if len(self.redirection_chain) > 1:
            unique_domains = set()
            for step in self.redirection_chain:
                if 'url' in step:
                    extracted = tldextract.extract(step.get('url', ''))
                    unique_domains.add(f"{extracted.domain}.{extracted.suffix}")
            
            if len(unique_domains) > 1:
                recommendations.append("Be cautious with URLs that redirect across multiple different domains")
        
        # General security recommendations
        if not recommendations:
            recommendations.append("Always verify the URL before entering sensitive information")
            recommendations.append("Use a password manager to avoid entering credentials on phishing sites")
            recommendations.append("Enable two-factor authentication where available")
        
        return recommendations
        
    def generate_report(self):
        """Generate a comprehensive security report based on all checks"""
        try:
            # Ensure all checks have been performed
            if not self.components:
                self.extract_components()
            if not self.typosquatting_results:
                self.check_typosquatting()
            if not self.whois_data:
                self.check_whois()
            if not self.ssl_info:
                self.verify_ssl()
            if not self.blacklist_results:
                self.check_blacklists()
            if not self.redirection_chain:
                self.analyze_redirections()
            
            # Calculate final risk score (cap at 100)
            final_risk_score = min(100, self.risk_score)
            
            # Determine risk level
            risk_level = "Safe"
            if final_risk_score >= 80:
                risk_level = "Critical Risk"
            elif final_risk_score >= 60:
                risk_level = "High Risk"
            elif final_risk_score >= 40:
                risk_level = "Medium Risk"
            elif final_risk_score >= 20:
                risk_level = "Low Risk"
            
            # Generate final report
            self.report = {
                'url': self.url,
                'normalized_url': self.normalized_url,
                'risk_score': final_risk_score,
                'risk_level': risk_level,
                'risk_factors': self.risk_factors,
                'components': self.components,
                'typosquatting': self.typosquatting_results,
                'whois': self.whois_data,
                'ssl': self.ssl_info,
                'blacklists': self.blacklist_results,
                'redirections': self.redirection_chain,
                'timestamp': datetime.now().isoformat(),
                'recommendations': self._generate_recommendations()
            }
            
            return self.report
            
        except Exception as e:
            return {
                'url': self.url,
                'error': f"Failed to generate report: {str(e)}",
                'risk_score': min(100, self.risk_score),
                'risk_level': "Unknown (Error)",
                'risk_factors': self.risk_factors,
                'timestamp': datetime.now().isoformat()
            }