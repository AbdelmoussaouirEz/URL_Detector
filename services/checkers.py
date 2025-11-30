import socket
import ssl
import requests
import dns.resolver
import whois
from datetime import datetime
from urllib.parse import urlparse
from typing import Tuple
import logging

from config.config import config
import socket
import ssl
import requests
import dns.resolver
import whois
from datetime import datetime
from urllib.parse import urlparse
from typing import Tuple
import logging

from config.config import config

logger = logging.getLogger(__name__)

class SecurityCheckers:
    """Collection of security checking functions"""
    
    def __init__(self):
        pass
    
    def check_https(self, url: str) -> Tuple[bool, str]:
        """
        Check if URL uses HTTPS
        Returns: (flagged, reason)
        """
        try:
            if url.startswith('https://') or 'https' in url:
                return False, "Uses secure HTTPS protocol"
            else:
                return True, "URL uses insecure HTTP protocol instead of HTTPS"
        except Exception as e:
            logger.error(f"HTTPS check error: {str(e)}")
            return False, "Could not determine protocol"
    
    def check_dns(self, url: str) -> Tuple[bool, str]:
        """
        Check if domain has valid DNS records
        Returns: (flagged, reason)
        """
        try:
            parsed = urlparse(url if url.startswith('http') else f'http://{url}')
            domain = parsed.netloc or parsed.path.split('/')[0]
            
            # Remove port if present
            domain = domain.split(':')[0]
            
            # Try to resolve DNS
            resolver = dns.resolver.Resolver()
            resolver.timeout = config.DNS_TIMEOUT
            resolver.lifetime = config.DNS_TIMEOUT
            
            answers = resolver.resolve(domain, 'A')
            
            if answers:
                return False, f"Valid DNS records found ({len(answers)} A records)"
            else:
                return True, "No DNS records found for domain"
                
        except dns.resolver.NXDOMAIN:
            return True, "Domain does not exist (NXDOMAIN)"
        except dns.resolver.Timeout:
            return True, "DNS lookup timed out"
        except Exception as e:
            logger.error(f"DNS check error: {str(e)}")
            return False, f"DNS check failed: {str(e)}"
    
    def check_ssl_certificate(self, url: str) -> Tuple[bool, str]:
        """
        Check if SSL certificate is valid
        Returns: (flagged, reason)
        """
        try:
            parsed = urlparse(url if url.startswith('http') else f'https://{url}')
            domain = parsed.netloc or parsed.path.split('/')[0]
            
            # Remove port if present
            domain = domain.split(':')[0]
            
            # Skip if not HTTPS
            if not url.startswith('https'):
                return False, "Not using HTTPS (SSL check skipped)"
            
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=config.SSL_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    
                    if not_after < datetime.now():
                        return True, "SSL certificate has expired"
                    
                    return False, f"Valid SSL certificate (expires {not_after.strftime('%Y-%m-%d')})"
                    
        except ssl.SSLError as e:
            return True, f"SSL certificate error: {str(e)}"
        except socket.timeout:
            return True, "SSL check timed out"
        except Exception as e:
            logger.error(f"SSL check error: {str(e)}")
            return False, f"Could not verify SSL certificate"
    
    def check_domain_age(self, url: str) -> Tuple[bool, str]:
        """
        Check domain age (flag if too new)
        Returns: (flagged, reason)
        """
        try:
            parsed = urlparse(url if url.startswith('http') else f'http://{url}')
            domain = parsed.netloc or parsed.path.split('/')[0]
            
            # Remove port if present
            domain = domain.split(':')[0]
            
            # Get WHOIS info
            w = whois.whois(domain)
            
            # Get creation date
            creation_date = w.creation_date
            
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                age_days = (datetime.now() - creation_date).days
                
                if age_days < config.DOMAIN_AGE_THRESHOLD:
                    return True, f"Domain registered only {age_days} days ago (suspicious)"
                else:
                    return False, f"Domain age: {age_days} days (registered {creation_date.strftime('%Y-%m-%d')})"
            else:
                return False, "Could not determine domain age"
                
        except Exception as e:
            logger.error(f"Domain age check error: {str(e)}")
            return False, "Could not check domain age"
    
    def check_abuseipdb(self, url: str) -> Tuple[bool, str]:
        """
        Check IP reputation using AbuseIPDB
        Returns: (flagged, reason)
        """
        if not config.ABUSEIPDB_ENABLED:
            return False, "AbuseIPDB check disabled (no API key)"
        
        try:
            parsed = urlparse(url if url.startswith('http') else f'http://{url}')
            domain = parsed.netloc or parsed.path.split('/')[0]
            domain = domain.split(':')[0]
            
            # Resolve domain to IP
            ip = socket.gethostbyname(domain)
            
            # Check AbuseIPDB
            headers = {
                'Key': config.ABUSEIPDB_API_KEY,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90
            }
            
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers=headers,
                params=params,
                timeout=config.API_TIMEOUT
            )
            
            if response.status_code == 200:
                data = response.json()['data']
                abuse_score = data['abuseConfidenceScore']
                total_reports = data['totalReports']
                
                if abuse_score > 25 or total_reports > 0:
                    return True, f"IP has abuse score of {abuse_score}% ({total_reports} reports)"
                else:
                    return False, f"Clean IP reputation (abuse score: {abuse_score}%)"
            else:
                return False, "AbuseIPDB check failed"
                
        except Exception as e:
            logger.error(f"AbuseIPDB check error: {str(e)}")
            return False, "Could not check AbuseIPDB"
    
    def check_google_safe_browsing(self, url: str) -> Tuple[bool, str]:
        """
        Check URL against Google Safe Browsing
        Returns: (flagged, reason)
        """
        if not config.GOOGLE_SAFE_BROWSING_ENABLED:
            return False, "Google Safe Browsing disabled (no API key)"
        
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={config.GOOGLE_SAFE_BROWSING_API_KEY}"
            
            payload = {
                "client": {
                    "clientId": "url-security-checker",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(api_url, json=payload, timeout=config.API_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                
                if 'matches' in data and len(data['matches']) > 0:
                    threat_type = data['matches'][0]['threatType']
                    return True, f"Flagged by Google Safe Browsing as {threat_type}"
                else:
                    return False, "Not flagged by Google Safe Browsing"
            else:
                return False, "Google Safe Browsing check failed"
                
        except Exception as e:
            logger.error(f"Google Safe Browsing error: {str(e)}")
            return False, "Could not check Google Safe Browsing"
    
    def check_virustotal(self, url: str) -> Tuple[bool, str]:
        """
        Check URL against VirusTotal
        Returns: (flagged, reason)
        """
        if not config.VIRUSTOTAL_ENABLED:
            return False, "VirusTotal check disabled (no API key)"
        
        try:
            headers = {
                'x-apikey': config.VIRUSTOTAL_API_KEY
            }
            
            # Submit URL for scanning
            response = requests.post(
                'https://www.virustotal.com/api/v3/urls',
                headers=headers,
                data={'url': url},
                timeout=config.API_TIMEOUT
            )
            
            if response.status_code == 200:
                data = response.json()
                analysis_id = data['data']['id']
                
                # Get analysis results
                analysis_response = requests.get(
                    f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
                    headers=headers,
                    timeout=config.API_TIMEOUT
                )
                
                if analysis_response.status_code == 200:
                    analysis_data = analysis_response.json()
                    stats = analysis_data['data']['attributes']['stats']
                    
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    total = sum(stats.values())
                    
                    if malicious > 0 or suspicious > 0:
                        return True, f"Detected by {malicious + suspicious}/{total} security vendors on VirusTotal"
                    else:
                        return False, f"Clean on VirusTotal (0/{total} detections)"
                else:
                    return False, "VirusTotal analysis failed"
            else:
                return False, "VirusTotal check failed"
                
        except Exception as e:
            logger.error(f"VirusTotal error: {str(e)}")
            return False, "Could not check VirusTotal"
    
    def check_redirects(self, url: str) -> Tuple[bool, str]:
        """
        Check for redirects WITHOUT following them (safe method)
        Returns: (flagged, reason)
        """
        try:
            parsed = urlparse(url if url.startswith('http') else f'http://{url}')
            original_domain = parsed.netloc
            
            # Make HEAD request (only headers, no content download)
            # allow_redirects=False means we DON'T follow the redirect
            response = requests.head(
                url,
                allow_redirects=False,  # SAFE: Don't actually follow
                timeout=5,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            
            # Check if there's a redirect
            if response.status_code in [301, 302, 303, 307, 308]:
                # There IS a redirect
                redirect_location = response.headers.get('Location', '')
                
                if redirect_location:
                    # Parse redirect destination
                    if redirect_location.startswith('http'):
                        redirect_domain = urlparse(redirect_location).netloc
                    else:
                        # Relative redirect
                        return False, "Redirect is relative (same domain)"
                    
                    # Check if redirecting to different domain
                    if original_domain != redirect_domain:
                        return True, f"Redirects to different domain: {original_domain} → {redirect_domain}"
                    else:
                        return False, f"Redirects within same domain ({response.status_code})"
                else:
                    return True, f"Has redirect ({response.status_code}) but no Location header (suspicious)"
            
            # No redirect detected
            return False, "No redirects detected"
            
        except requests.Timeout:
            return False, "Request timed out (could not check redirects)"
        except requests.ConnectionError:
            return False, "Connection failed (could not check redirects)"
        except Exception as e:
            logger.error(f"Redirect check error: {str(e)}")
            return False, f"Could not check redirects: {str(e)}"