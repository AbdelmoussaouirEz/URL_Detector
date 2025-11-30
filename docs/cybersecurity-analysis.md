# Cybersecurity Analysis Methodology

## Overview

This document explains the cybersecurity reasoning behind each check performed by the URL Intelligence Extractor and how they contribute to threat detection.

## Threat Landscape

### Common URL-Based Attacks

1. **Phishing** - Fake login pages impersonating legitimate services
2. **Malware Distribution** - URLs hosting or triggering malware downloads
3. **Social Engineering** - Manipulative URLs designed to extract sensitive information
4. **Credential Harvesting** - Fake authentication pages
5. **Drive-by Downloads** - Automatic malware installation upon visit
6. **Typosquatting** - Misspelled domains mimicking legitimate brands
7. **URL Shortener Abuse** - Hiding malicious destinations
8. **Open Redirect Exploitation** - Abusing trusted domains to redirect

## Detection Methodology

### Layer 1: Machine Learning Analysis

**Purpose**: Pattern recognition of known malicious URL characteristics

**Why It Matters**:
- Attackers follow predictable patterns (excessive special characters, suspicious keywords, unusual domain lengths)
- ML can detect subtle combinations of features that humans might miss
- Trained on thousands of labeled examples (malicious, phishing, defacement, benign)

**Features Analyzed** (16 total):

#### Structural Features
```python
'url_length'      # Malicious URLs often very long (obfuscation)
'count_dir'       # Deep directory structures hide intent
'fd_length'       # First directory length patterns
'tld_length'      # Unusual TLD lengths
```

**Cybersecurity Insight**: 
- Phishing URLs: Average length 75+ characters (legitimate: 30-50)
- Deep paths (`/login/auth/verify/confirm/`) indicate fake pages

#### Character Distribution
```python
'count-digits'    # Unusual digit ratios
'count-letters'   # Letter/digit balance
'count (.)'       # Multiple subdomains (suspicious)
'count-'          # Excessive hyphens
'count='          # Query parameters (tracking, redirects)
'count%'          # URL encoding (obfuscation)
'count@'          # Username in URL (phishing trick)
```

**Cybersecurity Insight**:
- Legitimate: `google.com` (balanced, clean)
- Suspicious: `g00gle-login-verify-account123.com` (mixed case, numbers, hyphens)

#### Protocol Indicators
```python
'count-https'     # Multiple HTTPS references (suspicious)
'count-http'      # HTTP in path (downgrade attack)
'count-www'       # WWW repetition
```

**Cybersecurity Insight**:
- URL like `https://site.com/https://paypal.com` tries to deceive
- HTTP in path suggests redirect or iframe attack

#### Pattern Recognition
```python
'sus_url'         # Suspicious keyword detection
'short_url'       # URL shortener detection
```

**Cybersecurity Insight**:
- Keywords: `login`, `verify`, `account`, `password`, `secure`
- Context matters: `bank-login.com` vs `chase.com/login`
- URL shorteners hide destination (common in phishing)

**ML Model Choice - XGBoost**:
- Handles non-linear relationships
- Feature importance ranking
- Resistant to overfitting
- ~99% accuracy on test set

---

### Layer 2: HTTPS/HTTP Protocol Analysis

**Purpose**: Verify secure communication channel

**Threat Detection**:
```
❌ http://paypal-verify.com/login
   ↓
   No encryption - credentials sent in plaintext
   Can be intercepted by man-in-the-middle attacks
```

**Why It Matters**:
- 95%+ of legitimate financial/e-commerce sites use HTTPS
- Lack of HTTPS in 2024 is a red flag
- Phishing sites often skip HTTPS (cost/complexity)

**However**: 
- Some phishing sites DO use HTTPS (Let's Encrypt is free)
- HTTPS ≠ trustworthy, just encrypted
- This is ONE indicator among many

---

### Layer 3: DNS Record Validation

**Purpose**: Verify domain exists and is properly configured

**Threat Detection**:
```python
try:
    answers = resolver.resolve(domain, 'A')
    # If successful, domain has valid DNS
except dns.resolver.NXDOMAIN:
    # Domain doesn't exist - very suspicious
```

**Why It Matters**:
1. **Typosquatting Detection**: `amozon.com` (no DNS) vs `amazon.com`
2. **Temporary Phishing Domains**: Set up, used briefly, taken down
3. **Misconfigured Attacks**: Attackers make DNS mistakes
4. **Dead Domains**: Old malicious campaigns

**Real-World Example**:
- Phishing campaign creates `paypal-secure-login.tk`
- Used for 48 hours
- DNS records removed after campaign
- Our check catches it if still referenced

---

### Layer 4: SSL Certificate Verification

**Purpose**: Validate website identity and encryption

**Threat Detection**:
```python
# What we check:
1. Certificate exists
2. Not expired
3. Issued by trusted CA
4. Domain matches certificate
```

**Why It Matters**:
- **Self-signed certificates**: Common in phishing (free, easy)
- **Expired certificates**: Abandoned or compromised sites
- **Domain mismatch**: Certificate for `site-a.com` but serving `site-b.com`

**Limitations**:
- Free CAs (Let's Encrypt) make this less effective
- But still catches lazy/incompetent attackers

---

### Layer 5: Domain Age Analysis

**Purpose**: Identify newly registered domains

**Threat Detection**:
```python
age_days = (datetime.now() - creation_date).days

if age_days < 30:
    # RED FLAG: Very new domain
```

**Why It Matters - Statistics**:
- **60%+ of phishing domains** are less than 1 week old
- **85%+ of phishing domains** are less than 1 month old
- Attackers create fresh domains for each campaign

**Attack Pattern**:
```
Day 0:  Register paypal-verify-account-2024.com
Day 1:  Set up phishing page
Day 2:  Send spam emails
Day 3:  Harvest credentials
Day 4:  Domain blacklisted
Day 5:  Abandon domain, repeat with new one
```

**Legitimate Sites**:
- `google.com`: Registered 1997 (27 years old)
- `amazon.com`: Registered 1994 (30 years old)
- New legitimate businesses exist, but rare in bulk

**Threshold**: 30 days (configurable)

---

### Layer 6: Redirect Detection (Safe Method)

**Purpose**: Identify hidden destinations without visiting them

**Threat Detection**:
```python
# Safe check - HEAD request only, don't follow
response = requests.head(url, allow_redirects=False)

if response.status_code in [301, 302, 307, 308]:
    redirect_location = response.headers.get('Location')
    # Analyze destination without visiting it
```

**Why It Matters - Attack Vectors**:

#### A. URL Shortener Abuse
```
Visible: bit.ly/secure123
Actually: http://malware-site.tk/stealer.exe
```

#### B. Open Redirect Exploitation
```
https://trusted-site.com/redirect?url=https://phishing.com
                      ↑
                 Legitimate domain in display
```

#### C. Chain Redirects
```
site1.com → site2.com → site3.com → malicious.com
```

**Why We Don't Follow**:
- ❌ Could trigger drive-by downloads
- ❌ Could execute malicious JavaScript
- ❌ Could log our IP/fingerprint
- ✅ HEAD request is safe (headers only)

**Detection Logic**:
```python
if original_domain != final_domain:
    # Redirect to different domain - suspicious
    # Examples:
    # - bit.ly → phishing-site.tk
    # - trusted.com → malicious.com
```

---

### Layer 7: AbuseIPDB Reputation Check

**Purpose**: Check if IP address has been reported for malicious activity

**Threat Detection**:
```python
# Resolve domain to IP
ip = socket.gethostbyname(domain)

# Check AbuseIPDB
abuse_score = data['abuseConfidenceScore']  # 0-100
total_reports = data['totalReports']

if abuse_score > 25 or total_reports > 0:
    # IP has bad reputation
```

**Why It Matters**:
- **Shared Hosting Abuse**: Malicious sites on known bad IPs
- **Botnet C&C Servers**: Command & control infrastructure
- **Spam Sources**: IPs used for spam campaigns
- **Historical Data**: IP was malicious before

**Community Intelligence**:
- Honeypots report attacks
- SOC teams report incidents
- Automated systems flag suspicious IPs

---

### Layer 8: Google Safe Browsing

**Purpose**: Check against Google's massive threat database

**Threat Detection**:
```python
threat_types = [
    "MALWARE",                        # Malware distribution
    "SOCIAL_ENGINEERING",            # Phishing
    "UNWANTED_SOFTWARE",             # PUPs, adware
    "POTENTIALLY_HARMFUL_APPLICATION" # Mobile threats
]
```

**Why It Matters - Scale**:
- Google crawls **billions** of URLs daily
- Machine learning + human review
- Real-time updates
- Chrome browser integration (2 billion+ users)

**Coverage**:
- Known phishing kits
- Malware distribution sites
- Drive-by download pages
- Compromised legitimate sites

**Limitation**: 
- New threats (0-day) not yet in database
- But covers 95%+ of known threats

---

### Layer 9: VirusTotal Multi-Engine Scan

**Purpose**: Aggregate detection from 90+ security vendors

**Threat Detection**:
```python
malicious = stats.get('malicious', 0)  # How many flagged as bad
suspicious = stats.get('suspicious', 0)
total = sum(stats.values())            # Total engines

detection_ratio = f"{malicious + suspicious}/{total}"
```

**Why It Matters - Consensus**:
- **1/90 detection**: Possible false positive
- **10/90 detection**: Likely threat
- **50/90 detection**: Definitely malicious

**Vendors Include**:
- Kaspersky, Symantec, McAfee, Avast, etc.
- URL scanners, reputation engines
- Signature-based and heuristic detection

**Use Cases**:
- Zero-day malware (some vendor might catch it)
- But exercise caution
```

---

## False Positive/Negative Mitigation

### False Positives (Flagging good URLs)

**Causes**:
- New legitimate businesses (domain age)
- Personal websites without HTTPS
- Regional domains (.tk, .ml) used legitimately

**Mitigation**:
- Multiple checks required for high-risk rating
- 1-2 flags = LOW risk (not blocked, just cautious)
- Provide detailed reasons (user can evaluate)

### False Negatives (Missing bad URLs)

**Causes**:
- Zero-day attacks (not in databases)
- Sophisticated attackers (proper HTTPS, old domains)
- Compromised legitimate sites

**Mitigation**:
- ML catches patterns even if not in databases
- Multiple independent checks
- Regular model retraining
- Community reporting mechanism (future)

---

## Threat Intelligence Integration

### Current Sources
- AbuseIPDB: IP reputation
- Google Safe Browsing: Known threats
- VirusTotal: Multi-vendor consensus
- PhishTank/OpenPhish: Phishing feeds

### Future Enhancements
- AlienVault OTX: Open threat exchange
- Cisco Talos: Threat intelligence
- Spamhaus: Domain/IP reputation
- Custom threat feeds

---

## Cybersecurity Best Practices Applied

1. **Defense in Depth**: Multiple independent layers
2. **Fail-Safe**: Failed checks don't block (graceful degradation)
3. **Least Privilege**: Minimal permissions required
4. **Transparency**: Clear reasoning for decisions
5. **Privacy**: No logging of user behavior
6. **Safety**: Never executes or follows suspicious URLs

---

**Next**: See [Design Decisions](design-decisions.md) for technical implementation choices.