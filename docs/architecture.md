# System Architecture

## Overview

The URL Intelligence Extractor follows a **microservices architecture** with clear separation of concerns, enabling maintainability, testability, and scalability.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Client Application                      │
│              (Browser, CLI, Python Script, etc.)            │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTP Request (POST /predict)
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                    FastAPI Application                       │
│                        (main.py)                            │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Request Validation & URL Preprocessing                │ │
│  └────────────────────────────────────────────────────────┘ │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                   Service Orchestration                      │
│                                                              │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────┐ │
│  │ Feature          │  │ Model            │  │ Security  │ │
│  │ Extractor        │  │ Predictor        │  │ Checkers  │ │
│  └────────┬─────────┘  └────────┬─────────┘  └─────┬─────┘ │
│           │                     │                    │       │
│           ↓                     ↓                    ↓       │
│  ┌──────────────────────────────────────────────────────┐   │
│  │           Data Aggregation & Analysis                │   │
│  └──────────────────┬───────────────────────────────────┘   │
│                     ↓                                        │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Scoring System                          │   │
│  │         (Calculate Risk Score & Level)               │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                    Response Generation                       │
│              (JSON with risk_score, checks, etc.)           │
└─────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. FastAPI Application Layer (`main.py`)

**Responsibilities:**
- HTTP request handling
- Input validation using Pydantic models
- Service orchestration
- Response formatting
- Error handling and logging
- API documentation (Swagger/ReDoc)

**Key Endpoints:**
- `GET /` - API information and available checkers
- `GET /health` - Health check and model status
- `POST /predict` - Main URL analysis endpoint
- `GET /docs` - Interactive API documentation

**Lifespan Management:**
- Initializes all services on startup
- Validates ML model loading
- Graceful shutdown handling

### 2. Feature Extractor Service (`services/feature_extractor.py`)

**Purpose:** Extract 16 structural and semantic features from URLs

**Features Extracted:**
1. `use_of_ip` - IP address detection
2. `count (.)` - Dot character count
3. `count-www` - WWW substring count
4. `count@` - At symbol count
5. `count_dir` - Directory depth
6. `count_embed_domain` - Embedded domain count
7. `short_url` - URL shortening service detection
8. `count%` - Percentage symbol count
9. `count-` - Hyphen count
10. `count=` - Equal sign count
11. `url_length` - Total character count
12. `sus_url` - Suspicious keyword detection
13. `fd_length` - First directory length
14. `tld_length` - Top-level domain length
15. `count-digits` - Numeric character count
16. `count-letters` - Alphabetic character count

**Dependencies:**
- `re` - Regular expressions for pattern matching
- `urllib.parse` - URL parsing utilities
- `tld` - Top-level domain extraction

### 3. Model Predictor Service (`services/model_predictor.py`)

**Purpose:** Execute ML predictions using trained XGBoost model

**Key Functions:**
- `load_model()` - Load pickled XGBoost model
- `is_loaded()` - Verify model availability
- `prepare_features()` - Convert feature dict to numpy array
- `predict()` - Generate prediction and confidence score

**Model Details:**
- **Algorithm:** XGBoost Binary Classifier
- **Input:** 16-dimensional feature vector
- **Output:** Binary label (0=safe, 1=not safe) + confidence
- **Label Mapping:** {0: "safe", 1: "not safe"}

**Feature Order (Critical):**
Features must be in exact training order for correct predictions.

### 4. Security Checkers Service (`services/checkers.py`)

**Purpose:** Execute 8 independent security verification checks

**Core Checks (Always Active):**
1. **HTTPS Verification** - Protocol security
   - Flags HTTP (insecure) vs HTTPS (secure)
   - Instant execution
   
2. **DNS Validation** - Domain resolution
   - Checks A record existence
   - Timeout: 5 seconds
   - Requires: `dnspython`
   
3. **SSL Certificate Verification** - Certificate validity
   - Validates CA signature
   - Checks expiration
   - Timeout: 10 seconds
   
4. **Domain Age Check** - Registration date analysis
   - Flags domains < 30 days old
   - Uses WHOIS data
   - Timeout: 10 seconds
   - Requires: `python-whois`
   
5. **Redirect Detection** - Redirect pattern analysis
   - Safe check (doesn't follow redirects)
   - Analyzes response headers
   - Timeout: 5 seconds

**Optional API Checks (Require Keys):**
6. **AbuseIPDB** - IP reputation lookup
   - API: ipv4/ipv6 reputation database
   - Requires: `ABUSEIPDB_API_KEY` in .env
   
7. **Google Safe Browsing** - Threat database
   - API: Google's threat intelligence
   - Requires: `GOOGLE_SAFE_BROWSING_API_KEY` in .env
   
8. **VirusTotal** - Multi-engine scanning
   - API: 70+ antivirus engines
   - Requires: `VIRUSTOTAL_API_KEY` in .env

**Configuration:**
- All checks have configurable timeouts (`config/config.py`)
- Graceful degradation if APIs unavailable
- Minimum 6 checks without API keys, maximum 9 with all keys

### 5. Scoring System Service (`services/scoring_system.py`)

**Purpose:** Aggregate check results into actionable risk metrics

**Calculations:**
```
risk_score = "X/Y" where:
  X = number of checks flagged
  Y = total checks executed

risk_percentage = (X / Y) * 100

risk_level = categorize(risk_percentage):
  - SAFE:     0-11%   (0-1 flags)
  - LOW:      12-33%  (2-3 flags)
  - MEDIUM:   34-55%  (4-5 flags)
  - HIGH:     56-77%  (6-7 flags)
  - CRITICAL: 78-100% (8-9 flags)

is_safe = (risk_percentage < 34%)
```

**Recommendations:**
- **SAFE:** "✅ SAFE: No security concerns detected."
- **LOW:** "⚠️ LOW RISK: Minor concerns detected. Proceed with caution."
- **MEDIUM:** "🔶 MEDIUM RISK: Multiple concerns detected. Not recommended."
- **HIGH:** "🔴 HIGH RISK: Strong avoidance recommended."
- **CRITICAL:** "⛔ CRITICAL: DO NOT VISIT - severe threats detected."

## Data Flow

### Request Processing Flow

```
1. Client → POST /predict {"url": "example.com"}
                ↓
2. FastAPI validates request (Pydantic)
                ↓
3. URL preprocessing (add https:// if missing)
                ↓
4. Feature Extraction
   - Extract 16 features from URL string
   - Return feature dictionary
                ↓
5. ML Prediction
   - Prepare feature vector
   - Load XGBoost model
   - Generate prediction + confidence
                ↓
6. Security Checks (Parallel Execution)
   - HTTPS check
   - DNS check
   - SSL check
   - Domain age check
   - Redirect check
   - [Optional] AbuseIPDB
   - [Optional] Google Safe Browsing
   - [Optional] VirusTotal
                ↓
7. Scoring System
   - Aggregate all check results
   - Calculate risk_score, risk_level
   - Generate recommendation
                ↓
8. Response Generation
   - Format URLResponse JSON
   - Include all checks detail
   - Return to client
```

## Performance Characteristics

### Latency Analysis

**Best Case (No API Keys):**
- Feature extraction: ~10ms
- ML prediction: ~50ms
- HTTPS check: ~1ms
- DNS check: ~100ms
- SSL check: ~500ms
- Domain age: ~2s
- Redirect check: ~100ms
- **Total:** ~2.8 seconds

**With API Keys:**
- AbuseIPDB: +500ms
- Google Safe Browsing: +300ms
- VirusTotal: +1s
- **Total:** ~4.6 seconds

### Optimization Strategies

**Current:**
- Sequential check execution
- No caching
- Single-threaded processing

**Future Improvements:**
1. **Async/Parallel Execution**
   - Run checks concurrently
   - Reduce total latency to ~3s
   
2. **Caching Layer (Redis)**
   - Cache ML predictions (1 hour TTL)
   - Cache DNS results (5 minutes)
   - Cache API responses (10 minutes)
   - Expected reduction: 50-80% for repeated URLs
   
3. **Database Integration**
   - Store historical analysis results
   - Build URL reputation database
   - Enable trend analysis

## Error Handling

### Service-Level Error Handling

Each service implements graceful degradation:

```python
try:
    result = security_checkers.check_https(url)
except Exception as e:
    logger.error(f"HTTPS check failed: {e}")
    # Continue with other checks
```

**Philosophy:** One check failure should not break entire analysis

### API-Level Error Handling

```python
@app.post("/predict")
async def predict_url(request: URLRequest):
    try:
        # Process URL
        return URLResponse(...)
    except ValueError as e:
        # 400 Bad Request
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        # 500 Internal Server Error
        raise HTTPException(status_code=500, detail=str(e))
```

## Security Considerations

### Input Validation
- URL length limited to 2048 characters
- Pydantic validation for request structure
- URL format validation before processing

### Safe Execution
- Redirect check does NOT follow redirects
- No JavaScript execution
- No file downloads
- Timeouts on all external calls

### Data Privacy
- No URL storage by default
- No user tracking
- API keys stored in environment variables
- Logging configurable (can disable URL logging)

## Testing Architecture

### Unit Tests (`tests/test_feature_extractor.py`)
- Test each feature extraction method independently
- Mock external dependencies
- Test edge cases (empty URLs, malformed inputs)
- Validate regex patterns
- **Coverage Target:** 100% of feature extractor

### Integration Tests (`tests/test_integration.py`)
- Test complete API request/response cycle
- Validate service interactions
- Test error handling across layers
- Verify response schema compliance
- **Test Client:** FastAPI TestClient with httpx

### Manual Tests (`test_urls.py`)
- Real-world URL validation
- 20 known URLs (10 safe, 10 phishing)
- Performance benchmarking
- Accuracy metrics calculation

### Coverage Targets
- **Overall:** Minimum 80% code coverage
- **Critical Paths:** 100% coverage
  - Scoring system logic
  - ML prediction pipeline
  - Response generation

## Deployment Architecture

### Development Environment
```bash
poetry install
poetry shell
python main.py
```

### Scaling Considerations

**Horizontal Scaling:**
- Stateless API design enables multiple instances
- Load balancer (nginx, HAProxy)
- No shared state between instances

**Vertical Scaling:**
- ML prediction benefits from CPU cores
- Memory requirement: ~500MB per instance
- Recommended: 2 CPU cores, 2GB RAM per instance

## Configuration Management

### Environment Variables (`.env`)
```bash
# Optional API Keys
ABUSEIPDB_API_KEY=your_key
GOOGLE_SAFE_BROWSING_API_KEY=your_key
VIRUSTOTAL_API_KEY=your_key
```

### Configuration File (`config/config.py`)
- Timeout settings for each checker
- Domain age threshold (default: 30 days)
- Logging configuration
- API endpoint settings

## Monitoring and Observability

### Logging
- **Level:** INFO for production
- **Format:** Structured JSON logs
- **Content:**
  - Request URLs (configurable)
  - Processing time per check
  - Errors and exceptions
  - Model prediction results

### Metrics (Future)
- Request rate (requests/second)
- Average latency per endpoint
- Error rate by check type
- ML prediction distribution
- Cache hit rate

### Health Checks
- `/health` endpoint
- Model loaded status
- Service availability
- Last successful check timestamp

---

## Technology Stack Summary

| Component | Technology | Purpose |
|-----------|-----------|---------|
| API Framework | FastAPI | Async web framework |
| ML Model | XGBoost | Binary classification |
| Validation | Pydantic | Request/response validation |
| Server | Uvicorn | ASGI server |
| Dependency Mgmt | Poetry | Package management |
| Testing | Pytest | Unit/integration tests |
| HTTP Client | httpx | Test client backend |
| DNS | dnspython | DNS resolution |
| WHOIS | python-whois | Domain age lookup |
| TLD Parsing | tld | Domain extraction |

---

**Next**: See [Design Decisions](design-decisions.md) for technical choices and reasoning.