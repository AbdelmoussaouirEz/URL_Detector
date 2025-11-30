# API Reference

Complete API documentation for the URL Intelligence Extractor.

## Base URL

```
http://localhost:8000
```

## Authentication

No authentication required for current version.

## Endpoints

### 1. Root Information

Get API information and available endpoints.

**Endpoint**: `GET /`

**Response**: `200 OK`

```json
{
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
    ...
  ]
}
```

---

### 2. Health Check

Check if the API and model are running properly.

**Endpoint**: `GET /health`

**Response**: `200 OK`

```json
{
  "status": "healthy",
  "model_loaded": true,
  "services": {
    "feature_extractor": "operational",
    "model_predictor": "operational"
  }
}
```

---

### 3. URL Analysis (Main Endpoint)

Perform comprehensive security analysis on a URL.

**Endpoint**: `POST /predict`

**Request Headers**:
```
Content-Type: application/json
```

**Request Body**:
```json
{
  "url": "string"
}
```

**Parameters**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| url | string | Yes | URL to analyze (1-2048 characters) |

**Example Request**:
```bash
curl -X POST "http://localhost:8000/predict" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

**Success Response**: `200 OK`

```json
{
  "url": "https://example.com",
  "risk_score": "2/9",
  "risk_percentage": 22.2,
  "risk_level": "LOW",
  "is_safe": false,
  "total_checks": 9,
  "flags_raised": 2,
  "checks": [
    {
      "name": "ML Model",
      "flagged": false,
      "score": 0,
      "reason": "ML model classified as 'safe' with 95.2% confidence"
    },
    {
      "name": "HTTPS Check",
      "flagged": true,
      "score": 1,
      "reason": "URL uses insecure HTTP protocol instead of HTTPS"
    },
    ...
  ],
  "recommendation": "⚠️ LOW RISK: Minor concerns detected. Proceed with caution.",
  "ml_prediction": "safe",
  "ml_confidence": 0.952
}
```

**Response Fields**:

| Field | Type | Description |
|-------|------|-------------|
| url | string | The analyzed URL |
| risk_score | string | Score in format "X/Y" (flags/total) |
| risk_percentage | float | Percentage of checks that flagged (0-100) |
| risk_level | string | Overall risk: SAFE, LOW, MEDIUM, HIGH, CRITICAL |
| is_safe | boolean | True if no flags raised |
| total_checks | integer | Total number of checks performed |
| flags_raised | integer | Number of checks that flagged issues |
| checks | array | Detailed results from each checker |
| recommendation | string | Human-readable recommendation |
| ml_prediction | string | ML model prediction (safe/not safe) |
| ml_confidence | float | ML model confidence (0.0-1.0) |

**Check Object Structure**:

```json
{
  "name": "string",        // Checker name
  "flagged": boolean,      // True if issue detected
  "score": integer,        // 0 or 1
  "reason": "string"       // Detailed explanation
}
```

**Error Responses**:

**400 Bad Request** - Invalid URL
```json
{
  "detail": "Invalid URL: URL cannot be empty"
}
```

**422 Unprocessable Entity** - Validation Error
```json
{
  "detail": [
    {
      "loc": ["body", "url"],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

**500 Internal Server Error** - Processing Error
```json
{
  "detail": "Error processing URL: [error message]"
}
```

---

## Risk Levels

| Level | Score Range | Description |
|-------|-------------|-------------|
| SAFE | 0/9 (0%) | No security concerns detected |
| LOW | 1-2/9 (11-22%) | Minor concerns, proceed with caution |
| MEDIUM | 3-4/9 (33-44%) | Multiple concerns detected |
| HIGH | 5-6/9 (55-66%) | Strongly recommend avoiding |
| CRITICAL | 7-9/9 (77-100%) | Serious threats, DO NOT VISIT |

---

## Security Checkers

### 1. ML Model
- **Type**: Machine Learning (XGBoost)
- **Checks**: 16 URL features
- **Output**: safe/not safe + confidence

### 2. HTTPS Check
- **Type**: Protocol Analysis
- **Checks**: Uses secure HTTPS protocol
- **Flags**: HTTP-only URLs

### 3. DNS Check
- **Type**: Domain Validation
- **Checks**: Valid DNS A records exist
- **Flags**: NXDOMAIN, timeouts

### 4. SSL Certificate
- **Type**: Certificate Validation
- **Checks**: Valid SSL certificate, not expired
- **Flags**: Invalid, expired, self-signed certificates

### 5. Domain Age
- **Type**: WHOIS Lookup
- **Checks**: Domain registration date
- **Flags**: Domains < 30 days old

### 6. Redirect Check
- **Type**: Safe Redirect Analysis
- **Checks**: HEAD request for redirects (doesn't follow)
- **Flags**: Redirects to different domains

### 7. AbuseIPDB (Optional)
- **Type**: IP Reputation
- **Checks**: IP abuse reports
- **Flags**: IPs with abuse score > 25%
- **Requires**: API key

### 8. Google Safe Browsing (Optional)
- **Type**: Threat Database
- **Checks**: Known malware, phishing, unwanted software
- **Flags**: URLs in Google's threat database
- **Requires**: API key

### 9. VirusTotal (Optional)
- **Type**: Multi-Engine Scan
- **Checks**: 90+ antivirus engines
- **Flags**: URLs with detections
- **Requires**: API key


---

## Rate Limiting

**Current**: No rate limiting implemented

**Future**: 
- 100 requests/minute per IP
- 1000 requests/hour per IP

---

## Examples

### Example 1: Safe URL

**Request**:
```json
{
  "url": "https://google.com"
}
```

**Response**:
```json
{
  "url": "https://google.com",
  "risk_score": "0/9",
  "risk_percentage": 0.0,
  "risk_level": "SAFE",
  "is_safe": true,
  "recommendation": "✅ SAFE: No security concerns detected."
}
```

### Example 2: Suspicious URL

**Request**:
```json
{
  "url": "http://paypal-verify-login.tk"
}
```

**Response**:
```json
{
  "url": "http://paypal-verify-login.tk",
  "risk_score": "7/9",
  "risk_percentage": 77.8,
  "risk_level": "CRITICAL",
  "is_safe": false,
  "checks": [
    {
      "name": "ML Model",
      "flagged": true,
      "reason": "Classified as 'not safe' with 98% confidence"
    },
    {
      "name": "HTTPS Check",
      "flagged": true,
      "reason": "Uses insecure HTTP protocol"
    },
    {
      "name": "Domain Age",
      "flagged": true,
      "reason": "Domain registered 3 days ago"
    },
    ...
  ],
  "recommendation": "🔴 CRITICAL: DO NOT VISIT THIS URL!"
}
```

### Example 3: URL Without Protocol

**Request**:
```json
{
  "url": "example.com"
}
```

**Auto-Corrected To**:
```
https://example.com
```

---

## Interactive Documentation

Visit `http://localhost:8000/docs` for:
- Swagger UI interface
- Try-it-out functionality
- Request/response examples
- Schema definitions

Visit `http://localhost:8000/redoc` for:
- Clean documentation layout
- Detailed descriptions
- Code examples

---

## Client Libraries

### Python

```python
import requests

def check_url(url: str) -> dict:
    response = requests.post(
        "http://localhost:8000/predict",
        json={"url": url}
    )
    return response.json()

# Usage
result = check_url("https://example.com")
print(f"Risk Level: {result['risk_level']}")
print(f"Safe: {result['is_safe']}")
```

### JavaScript

```javascript
async function checkURL(url) {
  const response = await fetch('http://localhost:8000/predict', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: url })
  });
  
  return await response.json();
}

// Usage
checkURL('https://example.com')
  .then(result => {
    console.log(`Risk Level: ${result.risk_level}`);
    console.log(`Safe: ${result.is_safe}`);
  });
```

### cURL

```bash
curl -X POST "http://localhost:8000/predict" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}' \
  | python -m json.tool
```
