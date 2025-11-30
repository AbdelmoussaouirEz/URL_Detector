from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
import uvicorn
from typing import Dict, Optional, List
from contextlib import asynccontextmanager
import logging
import sys

from services.feature_extractor import FeatureExtractor
from services.model_predictor import ModelPredictor
from services.checkers import SecurityCheckers
from services.scoring_system import ScoringSystem

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

feature_extractor = None
model_predictor = None
security_checkers = None
scoring_system = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler for startup and shutdown"""
    global feature_extractor, model_predictor, security_checkers, scoring_system
    try:
        logger.info("Starting Malicious URL Detection API...")
        logger.info("Loading ML model and initializing services...")
        
        feature_extractor = FeatureExtractor()
        model_predictor = ModelPredictor(model_path="xgb.pkl")
        security_checkers = SecurityCheckers()
        scoring_system = ScoringSystem()
        
        if not model_predictor.is_loaded():
            raise Exception("Model failed to load!")
        
        logger.info("API startup complete - all services ready")
    except Exception as e:
        logger.error(f"Startup failed: {str(e)}")
        raise
    
    yield
    
    logger.info("Shutting down API...")

app = FastAPI(
    title="Malicious URL Detection API",
    description="API for detecting malicious, phishing, and defacement URLs using Machine Learning",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str = Field(..., description="URL to analyze", min_length=1, max_length=2048)
    
    @field_validator('url')
    @classmethod
    def validate_url(cls, v):
        """Basic URL validation"""
        if not v or v.strip() == "":
            raise ValueError("URL cannot be empty")
        
        v = v.strip()
        
        if not v.startswith(('http://', 'https://', 'ftp://')):
            v = 'https://' + v
        
        return v
    
    model_config = {
        "json_schema_extra": {
            "examples": [{"url": "https://example.com/login"}]
        }
    }

class CheckResult(BaseModel):
    name: str
    flagged: bool
    score: int
    reason: str

class URLResponse(BaseModel):
    url: str
    risk_score: str
    risk_percentage: float
    risk_level: str
    is_safe: bool
    total_checks: int
    flags_raised: int
    checks: List[CheckResult]
    recommendation: str
    ml_prediction: Optional[str] = None
    ml_confidence: Optional[float] = None
    
    model_config = {
        "json_schema_extra": {
            "examples": [{
                "url": "https://example.com",
                "risk_score": "0/9",
                "risk_percentage": 0.0,
                "risk_level": "SAFE",
                "is_safe": True,
                "total_checks": 9,
                "flags_raised": 0,
                "checks": [],
                "recommendation": "✅ SAFE: No security concerns detected.",
                "ml_prediction": "safe",
                "ml_confidence": 0.95
            }]
        }
    }

@app.get("/", tags=["Info"])
async def root():
    """Root endpoint with API information"""
    return {
        "message": "Malicious URL Detection API - Multi-Layer Security Scanner",
        "version": "2.0.0",
        "model": "XGBoost + 9 Security Checkers",
        "endpoints": {
            "/predict": "POST - Comprehensive URL security check",
            "/health": "GET - Health check",
            "/docs": "GET - Interactive API documentation",
            "/redoc": "GET - Alternative API documentation"
        },
        "checkers": [
            "ML Model (XGBoost)",
            "HTTPS/HTTP Check",
            "DNS Record Check",
            "SSL Certificate Check",
            "Domain Age Check",
            "AbuseIPDB (if enabled)",
            "Google Safe Browsing (if enabled)",
            "VirusTotal (if enabled)",
            "Redirect Check (Safe - doesn't follow)",
        ]
    }

@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint"""
    is_healthy = model_predictor.is_loaded()
    return {
        "status": "healthy" if is_healthy else "unhealthy",
        "model_loaded": is_healthy,
        "services": {
            "feature_extractor": "operational",
            "model_predictor": "operational" if is_healthy else "failed"
        }
    }

@app.post("/predict", response_model=URLResponse, tags=["Prediction"])
async def predict_url(request: URLRequest):
    """
    Comprehensive URL security check using multiple layers
    
    Performs 9 different security checks:
    1. ML Model prediction
    2. HTTPS/HTTP protocol check
    3. DNS record validation
    4. SSL certificate check
    5. Domain age check
    6. AbuseIPDB reputation check (if enabled)
    7. Google Safe Browsing check (if enabled)
    8. VirusTotal scan (if enabled)
    9. Redirect check (safe - doesn't follow)
    
    Returns a risk score (e.g., 2/9) where lower is better.
    """
    try:
        url = request.url
        logger.info(f"Processing URL: {url}")
        
        checks = []
        
        try:
            features = feature_extractor.extract_features(url)
            prediction, confidence = model_predictor.predict(features)
            
            ml_flagged = prediction.lower() == "not safe"
            ml_reason = f"ML model classified as '{prediction}' with {confidence*100:.1f}% confidence"
            
            checks.append({
                'name': 'ML Model',
                'flagged': ml_flagged,
                'score': 1 if ml_flagged else 0,
                'reason': ml_reason
            })
        except Exception as e:
            logger.error(f"ML check error: {str(e)}")
            checks.append({
                'name': 'ML Model',
                'flagged': False,
                'score': 0,
                'reason': f"ML check failed: {str(e)}"
            })
        
        try:
            https_flagged, https_reason = security_checkers.check_https(url)
            checks.append({
                'name': 'HTTPS Check',
                'flagged': https_flagged,
                'score': 1 if https_flagged else 0,
                'reason': https_reason
            })
        except Exception as e:
            logger.error(f"HTTPS check error: {str(e)}")
        
        try:
            dns_flagged, dns_reason = security_checkers.check_dns(url)
            checks.append({
                'name': 'DNS Check',
                'flagged': dns_flagged,
                'score': 1 if dns_flagged else 0,
                'reason': dns_reason
            })
        except Exception as e:
            logger.error(f"DNS check error: {str(e)}")
        
        try:
            ssl_flagged, ssl_reason = security_checkers.check_ssl_certificate(url)
            checks.append({
                'name': 'SSL Certificate',
                'flagged': ssl_flagged,
                'score': 1 if ssl_flagged else 0,
                'reason': ssl_reason
            })
        except Exception as e:
            logger.error(f"SSL check error: {str(e)}")
        
        try:
            age_flagged, age_reason = security_checkers.check_domain_age(url)
            checks.append({
                'name': 'Domain Age',
                'flagged': age_flagged,
                'score': 1 if age_flagged else 0,
                'reason': age_reason
            })
        except Exception as e:
            logger.error(f"Domain age check error: {str(e)}")
        
        try:
            abuse_flagged, abuse_reason = security_checkers.check_abuseipdb(url)
            checks.append({
                'name': 'AbuseIPDB',
                'flagged': abuse_flagged,
                'score': 1 if abuse_flagged else 0,
                'reason': abuse_reason
            })
        except Exception as e:
            logger.error(f"AbuseIPDB check error: {str(e)}")
        
        try:
            gsb_flagged, gsb_reason = security_checkers.check_google_safe_browsing(url)
            checks.append({
                'name': 'Google Safe Browsing',
                'flagged': gsb_flagged,
                'score': 1 if gsb_flagged else 0,
                'reason': gsb_reason
            })
        except Exception as e:
            logger.error(f"Google Safe Browsing error: {str(e)}")
        
        try:
            vt_flagged, vt_reason = security_checkers.check_virustotal(url)
            checks.append({
                'name': 'VirusTotal',
                'flagged': vt_flagged,
                'score': 1 if vt_flagged else 0,
                'reason': vt_reason
            })
        except Exception as e:
            logger.error(f"VirusTotal error: {str(e)}")
        
        try:
            redirect_flagged, redirect_reason = security_checkers.check_redirects(url)
            checks.append({
                'name': 'Redirect Check',
                'flagged': redirect_flagged,
                'score': 1 if redirect_flagged else 0,
                'reason': redirect_reason
            })
        except Exception as e:
            logger.error(f"Redirect check error: {str(e)}")
        
        score_result = scoring_system.calculate_score(checks)
        
        response = URLResponse(
            url=url,
            risk_score=score_result['risk_score'],
            risk_percentage=score_result['risk_percentage'],
            risk_level=score_result['risk_level'],
            is_safe=score_result['is_safe'],
            total_checks=score_result['total_checks'],
            flags_raised=score_result['flags_raised'],
            checks=[CheckResult(**check) for check in checks],
            recommendation=score_result['recommendation'],
            ml_prediction=prediction if 'prediction' in locals() else None,
            ml_confidence=round(confidence, 4) if 'confidence' in locals() else None
        )
        
        logger.info(f"Analysis complete: {score_result['risk_score']} ({score_result['risk_level']})")
        return response
        
    except ValueError as e:
        logger.warning(f"Validation error for URL '{request.url}': {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid URL: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Error processing URL '{request.url}': {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error processing URL: {str(e)}"
        )

if __name__ == "__main__":
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=8000,
        log_level="info"
    )