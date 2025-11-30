# Cybersecurity-Oriented URL Intelligence Extractor

> A comprehensive multi-layer security analysis tool for URL threat detection.

## 🎯 Overview

This tool provides **9-layer security analysis** for URLs, combining XGBoost machine learning with multiple security checks to identify malicious URLs.

### Key Features

- 🤖 **Machine Learning** - XGBoost model trained on malicious URL patterns
- 🔒 **Protocol Analysis** - HTTPS/HTTP security verification
- 🌐 **DNS & SSL** - Domain existence and certificate validity checks
- ⏰ **Domain Age** - New domain detection
- 🛡️ **Threat Intelligence** - AbuseIPDB, Google Safe Browsing, VirusTotal (optional)
- 📊 **Risk Scoring** - Detailed risk score with recommendations

## 🚀 Quick Start

### Installation

```bash
git clone <repository-url>
cd URL_project
poetry install
cp .env.example .env  # Optional: Add API keys
```

### Usage

```bash
# Start API
poetry run python main.py
```

**API Request:**

```bash
curl -X POST "http://localhost:8000/predict" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

**Example Response:**

```json
{
  "url": "https://example.com",
  "risk_score": "2/9",
  "risk_level": "LOW",
  "is_safe": false,
  "checks": [
    {
      "name": "ML Model",
      "flagged": false,
      "reason": "ML model classified as 'safe'"
    }
    // ... other checks
  ]
}
```

## 🔍 Security Checks

1. **ML Analysis**: XGBoost Classifier (99% accuracy)
2. **HTTPS Check**: Verifies secure protocol
3. **DNS Validation**: Checks A records
4. **SSL Verification**: Validates certificate
5. **Domain Age**: Flags domains < 30 days
6. **Redirect Check**: Safe analysis without following
7. **AbuseIPDB**: IP reputation (Optional)
8. **Google Safe Browsing**: Threat database (Optional)
9. **VirusTotal**: Antivirus scan (Optional)

## 📊 Risk Scoring

| Risk Level | Description |
|------------|-------------|
| **SAFE** | No concerns |
| **LOW** | Minor concerns |
| **MEDIUM** | Multiple concerns |
| **HIGH** | Strong avoidance recommended |
| **CRITICAL** | DO NOT VISIT |

## 🧪 Testing

### Running Tests

The project includes comprehensive unit and integration tests:

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_feature_extractor.py -v
pytest tests/test_integration.py -v
```

### Test Suites

**Unit Tests** (`tests/test_feature_extractor.py`):
- Tests all 16 feature extraction methods
- Validates IP address detection 
- Tests embedded domain counting
- Verifies URL shortener detection
- Tests suspicious keyword detection

**Integration Tests** (`tests/test_integration.py`):
- Tests complete API request/response flow
- Validates risk_score format and calculation
- Tests error handling
- Verifies ML model binary classification
- Ensures all 9 security checks execute

### Manual Testing Script

Use `test_urls.py` to test the API with sample URLs:

```bash
# Start the API server first
python main.py

# In another terminal, run the test script
python test_urls.py
```

The script tests 20 URLs (10 safe, 10 malicious) and displays detailed results including risk scores, predictions, and accuracy metrics.

## 🔧 Development

```bash
# Run tests
poetry run pytest

# Format code
poetry run black .
```

## 📁 Project Structure

```
URL_project/
├── main.py              # FastAPI application
├── services/            # Core services
│   ├── feature_extractor.py
│   ├── model_predictor.py
│   ├── checkers.py
│   └── scoring_system.py
├── config/              # Configuration
├── tests/               # Test suites
├── docs/                # Documentation
└── xgb.pkl             # Trained model
```
