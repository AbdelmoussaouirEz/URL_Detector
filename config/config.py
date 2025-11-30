import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Configuration for external API services"""
    
    # AbuseIPDB Configuration
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
    ABUSEIPDB_ENABLED = bool(ABUSEIPDB_API_KEY)
    
    # Google Safe Browsing Configuration
    GOOGLE_SAFE_BROWSING_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '')
    GOOGLE_SAFE_BROWSING_ENABLED = bool(GOOGLE_SAFE_BROWSING_API_KEY)
    
    # VirusTotal Configuration
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
    VIRUSTOTAL_ENABLED = bool(VIRUSTOTAL_API_KEY)
    
    # Checker timeouts (seconds)
    DNS_TIMEOUT = 5
    SSL_TIMEOUT = 5
    API_TIMEOUT = 10
    
    # Domain age threshold (days)
    DOMAIN_AGE_THRESHOLD = 30  # Flag domains younger than 30 days
    
    @classmethod
    def get_enabled_checkers(cls):
        """Return list of enabled checker names"""
        checkers = [
            'ML Model',
            'HTTPS Check',
            'DNS Check',
            'SSL Certificate',
            'Domain Age'
        ]
        
        if cls.ABUSEIPDB_ENABLED:
            checkers.append('AbuseIPDB')
        
        if cls.GOOGLE_SAFE_BROWSING_ENABLED:
            checkers.append('Google Safe Browsing')
        
        if cls.VIRUSTOTAL_ENABLED:
            checkers.append('VirusTotal')
        
        return checkers

config = Config()