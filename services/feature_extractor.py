import re
from urllib.parse import urlparse
from tld import get_tld
from typing import Dict
import logging

logger = logging.getLogger(__name__)

class FeatureExtractor:
    """Service for extracting features from URLs"""
    
    def __init__(self):
        self.shortening_pattern = (
            r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
            r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
            r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
            r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
            r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
            r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
            r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
            r'tr\.im|link\.zip\.net'
        )
    
    def having_ip_address(self, url: str) -> int:
        match = re.search(
            r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'  # IPv4
            r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\/)|'  # IPv4 hexadecimal
            r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',  # IPv6
            url
        )
        return 1 if match else 0

    def no_of_embed(self, url: str) -> int:
        urlpath = urlparse(url).path
        return urlpath.count('//')

    def extract_features(self, url: str) -> Dict[str, int]:
        """Extract all features from a URL"""
        try:
            features = {
                'use_of_ip': self.having_ip_address(url),
                'count (.)': url.count('.'),
                'count-www': url.count('www'),
                'count@': url.count('@'),
                'count_dir': self.count_directories(url),
                'count_embed_domain': self.no_of_embed(url),
                'short_url': self.shortening_service(url),
                'count%': url.count('%'),
                'count-': url.count('-'),
                'count=': url.count('='),
                'url_length': len(url),
                'sus_url': self.suspicious_words(url),
                'fd_length': self.fd_length(url),
                'tld_length': self.tld_length(url),
                'count-digits': self.digit_count(url),
                'count-letters': self.letter_count(url)
            }
            logger.info(f"Extracted features: {features}")
            return features
        except Exception as e:
            logger.error(f"Error extracting features: {str(e)}")
            raise
    
    def count_directories(self, url: str) -> int:
        """Count number of directories in URL"""
        urlpath = urlparse(url).path
        return urlpath.count('/')
    
    def shortening_service(self, url: str) -> int:
        """Check if URL uses a shortening service"""
        match = re.search(self.shortening_pattern, url, flags=re.IGNORECASE)
        return 1 if match else 0
    
    def suspicious_words(self, url: str) -> int:
        """
        Enhanced suspicious URL detection focusing on contextual patterns
        rather than just word presence to reduce false positives
        """
        # Convert to lowercase for case-insensitive matching
        url_lower = url.lower()
        
        # High-confidence suspicious patterns
        suspicious_patterns = [
            # Pattern 1: Security words in domain name (not just path)
            r'^(?:[a-z0-9-]*\.)?(security|auth|login|verify|password|account|credential|token)\.',
            
            # Pattern 2: Brand + security word combinations (paypal-login.com)
            r'(paypal|bank|amazon|apple|google|microsoft|netflix|facebook|instagram)[-_\.](login|verify|security|account|password|auth)',
            
            # Pattern 3: Brand misspellings with security context
            r'(paypa1|paypai|arnazon|micr0soft|go0gle|app1e|faceb00k)[-_\.](login|verify|account)',
            
            # Pattern 4: Multiple security words in subdomain/path
            r'(login|auth|account).*(password|secure|verify)|(password|secure).*(login|auth|account)',
            
            # Pattern 5: High-risk words that are rarely legitimate in domains
            r'credential|passwd|pwd[0-9]|ssn[0-9]|socialsecurity|otp[0-9]|mfa[0-9]',
            
            # Pattern 6: Suspicious TLD patterns
            r'\.(tk|ml|ga|cf|gq|xyz)/(login|auth|admin|secure|account|verify)',
        ]
        
        # Check for high-confidence patterns first
        for pattern in suspicious_patterns:
            if re.search(pattern, url_lower):
                return 1
        
        # Medium-confidence: Individual high-risk words in specific contexts
        high_risk_words = [
            r'credential', r'password', r'passwd', r'pwd', r'pin', r'token', 
            r'otp', r'mfa', r'2fa', r'biometric', r'ssn', r'socialsecurity'
        ]
        
        # Only flag if these high-risk words appear in domain or key positions
        domain = url_lower.split('/')[0]  # Get domain part only
        for word in high_risk_words:
            if re.search(word, domain):  # Only check in domain, not full path
                return 1
        
        # Low-confidence: Original word list but with context awareness
        original_words = r'access|accounts|auth|security|portal|user|admin|identity|login|' \
                        r'privilege|validation|authorize|authentication|session|' \
                        r'transaction|validate|confirmation|billinginfo|accountinfo|' \
                        r'invoiceinfo|orderinfo|payment'
        
        # Only flag original words if they appear in suspicious combinations
        if re.search(original_words, url_lower, re.IGNORECASE):
            # Additional checks to reduce false positives
            words_found = re.findall(original_words, url_lower, re.IGNORECASE)
            
            # If multiple suspicious words found, more likely to be malicious
            if len(words_found) >= 2:
                return 1
            
            # If single word but in domain name (more suspicious)
            domain = url_lower.split('/')[0]
            if re.search(original_words, domain, re.IGNORECASE):
                return 1
        
        return 0
    
    def fd_length(self, url: str) -> int:
        """Get first directory length"""
        urlpath = urlparse(url).path
        try:
            return len(urlpath.split('/')[1])
        except:
            return 0
    
    def tld_length(self, url: str) -> int:
        """Get top-level domain length"""
        try:
            tld = get_tld(url, fail_silently=True)
            return len(tld) if tld else -1
        except:
            return -1
    
    def digit_count(self, url: str) -> int:
        """Count digits in URL"""
        return sum(1 for char in url if char.isdigit())
    
    def letter_count(self, url: str) -> int:
        """Count letters in URL"""
        return sum(1 for char in url if char.isalpha())