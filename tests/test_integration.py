"""
Integration tests for the complete API
"""

import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


class TestAPIEndpoints:
    """Test API endpoints and full request/response flow"""
    
    def test_root_endpoint(self):
        """Test root endpoint returns API information"""
        response = client.get("/")
        
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "version" in data
        assert "checkers" in data
    
    def test_health_endpoint(self):
        """Test health check endpoint"""
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] in ["healthy", "unhealthy"]
        assert "model_loaded" in data
    
    def test_predict_endpoint_valid_url(self):
        """Test prediction endpoint with valid URL"""
        response = client.post(
            "/predict",
            json={"url": "https://google.com"}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Check response structure - should have risk_score, not safety_score
        assert "url" in data
        assert "risk_score" in data
        assert "safety_score" not in data  # Ensure old field is gone
        assert "risk_level" in data
        assert "is_safe" in data
        assert "checks" in data
        assert "recommendation" in data
        
        # Check types
        assert isinstance(data["checks"], list)
        assert isinstance(data["is_safe"], bool)
        assert isinstance(data["risk_percentage"], float)
    
    def test_predict_response_has_all_checks(self):
        """Test that response includes results from checkers"""
        response = client.post(
            "/predict",
            json={"url": "https://example.com"}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Should have at least 6 checks without API keys (ML, HTTPS, DNS, SSL, Domain Age, Redirect)
        assert len(data["checks"]) >= 5
        
        # Check that each check has required fields
        for check in data["checks"]:
            assert "name" in check
            assert "flagged" in check
            assert "score" in check
            assert "reason" in check
    
    def test_predict_risk_score_format(self):
        """Test risk score format (X/Y)"""
        response = client.post(
            "/predict",
            json={"url": "https://google.com"}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Score should be in format "X/Y"
        score = data["risk_score"]
        assert "/" in score
        
        parts = score.split("/")
        assert len(parts) == 2
        assert parts[0].isdigit()
        assert parts[1].isdigit()
        
        # Total checks should match
        assert int(parts[1]) == data["total_checks"]
        assert int(parts[0]) == data["flags_raised"]
    
    def test_predict_ml_prediction_binary(self):
        """Test that ML prediction uses binary classification"""
        response = client.post(
            "/predict",
            json={"url": "https://google.com"}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert "ml_prediction" in data
        
        # Should be binary: "safe" or "not safe"
        if data["ml_prediction"]:
            assert data["ml_prediction"] in ["safe", "not safe"]
        
        if data.get("ml_confidence"):
            assert 0.0 <= data["ml_confidence"] <= 1.0
    
    def test_openapi_schema_available(self):
        """Test that OpenAPI schema is available"""
        response = client.get("/openapi.json")
        assert response.status_code == 200
        
        schema = response.json()
        assert "openapi" in schema
        assert "info" in schema
        assert "paths" in schema


class TestErrorHandling:
    """Test error handling and edge cases"""
    
    def test_very_long_url(self):
        """Test handling of very long URLs"""
        long_url = "https://example.com/" + "a" * 3000
        
        response = client.post(
            "/predict",
            json={"url": long_url}
        )
        
        # Should either process or reject gracefully
        assert response.status_code in [200, 400, 422]
    
    def test_url_with_special_characters(self):
        """Test URL with special characters"""
        url = "https://example.com/path?query=value&key=123%20test"
        
        response = client.post(
            "/predict",
            json={"url": url}
        )
        
        assert response.status_code == 200
    
    def test_invalid_json_request(self):
        """Test handling of invalid JSON"""
        response = client.post(
            "/predict",
            data="not json",
            headers={"Content-Type": "application/json"}
        )
        
        assert response.status_code == 422


if __name__ == "__main__":
    pytest.main([__file__, "-v"])