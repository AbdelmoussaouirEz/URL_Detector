"""
Unit tests for Feature Extractor Service
"""

import pytest
from services.feature_extractor import FeatureExtractor


class TestFeatureExtractor:
    """Test suite for FeatureExtractor class"""
    
    @pytest.fixture
    def extractor(self):
        """Create a FeatureExtractor instance for testing"""
        return FeatureExtractor()
    
    def test_extract_features_returns_dict(self, extractor):
        """Test that extract_features returns a dictionary"""
        url = "https://example.com"
        features = extractor.extract_features(url)
        
        assert isinstance(features, dict)
        assert len(features) == 16  # Should have 16 features
    
    def test_extract_features_has_all_required_keys(self, extractor):
        """Test that all 16 required features are present"""
        url = "https://example.com"
        features = extractor.extract_features(url)
        
        required_keys = [
            'use_of_ip', 'count (.)', 'count-www', 'count@', 'count_dir',
            'count_embed_domain', 'short_url', 'count%', 'count-', 
            'count=', 'url_length', 'sus_url', 'fd_length', 'count-digits',
            'tld_length', 'count-letters'
        ]
        
        for key in required_keys:
            assert key in features, f"Missing feature: {key}"
    
    def test_count_dots(self, extractor):
        """Test dot counting"""
        url = "https://sub.example.com"
        features = extractor.extract_features(url)
        assert features['count (.)'] == 2
    
    def test_count_www(self, extractor):
        """Test www counting"""
        url = "https://www.example.com"
        features = extractor.extract_features(url)
        assert features['count-www'] == 1
    
    def test_count_at_symbol(self, extractor):
        """Test @ symbol counting"""
        url = "https://user@example.com"
        features = extractor.extract_features(url)
        assert features['count@'] == 1
    
    def test_count_directories(self, extractor):
        """Test directory counting"""
        url = "https://example.com/path/to/page"
        features = extractor.extract_features(url)
        assert features['count_dir'] == 3  # Three slashes
    
    def test_url_length(self, extractor):
        """Test URL length calculation"""
        url = "https://example.com"
        features = extractor.extract_features(url)
        assert features['url_length'] == len(url)
    
    def test_digit_count(self, extractor):
        """Test digit counting"""
        url = "https://example123.com"
        features = extractor.extract_features(url)
        assert features['count-digits'] == 3
    
    def test_letter_count(self, extractor):
        """Test letter counting"""
        url = "https://example.com"
        features = extractor.extract_features(url)
        # Count only letters, not special characters
        expected = sum(1 for char in url if char.isalpha())
        assert features['count-letters'] == expected
    
    def test_shortening_service_detection_positive(self, extractor):
        """Test URL shortener detection - should detect"""
        urls = [
            "https://bit.ly/xyz",
            "https://goo.gl/abc",
            "https://t.co/test"
        ]
        
        for url in urls:
            features = extractor.extract_features(url)
            assert features['short_url'] == 1, f"Should detect shortener in {url}"
    
    def test_shortening_service_detection_negative(self, extractor):
        """Test URL shortener detection - should not detect"""
        urls = [
            "https://google.com",
            "https://facebook.com",
            "https://example.com"
        ]
        
        for url in urls:
            features = extractor.extract_features(url)
            assert features['short_url'] == 0, f"Should not detect shortener in {url}"
    
    def test_suspicious_words_detection(self, extractor):
        """Test suspicious keyword detection"""
        # Suspicious URL (has 'login' in domain)
        url1 = "https://bank-login.com"
        features1 = extractor.extract_features(url1)
        assert features1['sus_url'] == 1
        
        # Normal URL
        url2 = "https://example.com/page"
        features2 = extractor.extract_features(url2)
        assert features2['sus_url'] == 0
    
    def test_tld_length(self, extractor):
        """Test TLD length extraction"""
        url = "https://example.com"
        features = extractor.extract_features(url)
        assert features['tld_length'] == 3  # "com"
    
    def test_tld_length_unknown(self, extractor):
        """Test TLD length with invalid TLD"""
        url = "https://invalid_url_without_tld"
        features = extractor.extract_features(url)
        assert features['tld_length'] == -1
    
    def test_first_directory_length(self, extractor):
        """Test first directory length"""
        url = "https://example.com/test/path"
        features = extractor.extract_features(url)
        assert features['fd_length'] == 4  # "test"
    
    def test_first_directory_length_no_path(self, extractor):
        """Test first directory length with no path"""
        url = "https://example.com"
        features = extractor.extract_features(url)
        assert features['fd_length'] == 0
    
    def test_special_characters(self, extractor):
        """Test special character counting"""
        url = "https://example.com/path?query=value&key=123%20test"
        features = extractor.extract_features(url)
        
        assert features['count%'] >= 1
        assert features['count='] >= 2
        assert features['count-'] >= 0
    
    def test_complex_malicious_url_pattern(self, extractor):
        """Test feature extraction on a complex suspicious URL"""
        url = "http://paypal-verify-account-secure-login.tk/auth?token=xyz&redirect=http://malware.com"
        features = extractor.extract_features(url)
        
        # Should have multiple suspicious indicators
        assert features['sus_url'] == 1  # Has 'verify', 'account', 'login'
        assert features['url_length'] > 50  # Long URL
        assert features['count-'] > 3  # Many hyphens
        assert features['count='] > 0  # Has query parameters
    
    def test_legitimate_url_pattern(self, extractor):
        """Test feature extraction on a legitimate URL"""
        url = "https://www.google.com/search?q=test"
        features = extractor.extract_features(url)
        
        assert features['count-www'] == 1
        assert features['short_url'] == 0
    
    def test_empty_url_handling(self, extractor):
        """Test handling of edge cases"""
        # This should not crash
        try:
            url = ""
            features = extractor.extract_features(url)
            assert features['url_length'] == 0
        except Exception:
            pytest.fail("Should handle empty URL gracefully")
    
    def test_having_ip_address(self, extractor):
        """Test IP address detection"""
        # IPv4
        assert extractor.having_ip_address("http://192.168.1.1/test") == 1
        assert extractor.having_ip_address("http://10.0.0.1/") == 1
        
        # IPv4 Hex
        assert extractor.having_ip_address("http://0x7F.0x00.0x00.0x01/") == 1
        
        # Normal domain
        assert extractor.having_ip_address("http://google.com") == 0
    
    def test_no_of_embed(self, extractor):
        """Test embedded domain count (//)"""
        # Normal URL (no // in path)
        assert extractor.no_of_embed("https://google.com") == 0
        assert extractor.no_of_embed("https://google.com/path") == 0
        
        # Suspicious URL (multiple // in path)
        assert extractor.no_of_embed("https://google.com//redirect//test") == 2
        assert extractor.no_of_embed("http://example.com//wp-admin") == 1

    def test_feature_values_are_integers(self, extractor):
        """Test that all feature values are integers"""
        url = "https://example.com/test"
        features = extractor.extract_features(url)
        
        for key, value in features.items():
            assert isinstance(value, int), f"Feature {key} should be int, got {type(value)}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])