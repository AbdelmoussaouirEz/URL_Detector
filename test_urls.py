"""
URL Validation Test Script

Tests the Malicious URL Detection API with a set of known safe and malicious URLs.
This script sends POST requests to the API and displays results for each URL.

Usage:
    1. Start the API server: python main.py
    2. Run this script: python test_urls.py
"""

import requests
import json
from typing import List, Tuple

API_URL = "http://localhost:8000/predict"

# Test dataset: (URL, expected_label)
# 0 = safe, 1 = not safe
TEST_URLS: List[Tuple[str, int]] = [
    # Safe URLs (0)
    ("www.1up.com/do/gameOverview?cId=3159391", 0),
    ("psx.ign.com/articles/131/131835p1.html", 0),
    ("wii.gamespy.com/wii/cursed-mountain/", 0),
    ("wii.ign.com/objects/142/14270799.html", 0),
    ("xbox360.gamespy.com/xbox-360/dead-space/", 0),
    ("xbox360.ign.com/objects/850/850402.html", 0),
    ("games.teamxbox.com/xbox-360/1860/Dead-Space/", 0),
    ("www.gamespot.com/xbox360/action/deadspace/", 0),
    ("en.wikipedia.org/wiki/Dead_Space_(video_game)", 0),
    ("www.angelfire.com/goth/devilmaycrytonite/", 0),
    
    # Malicious URLs (1)
    ("nobell.it/70ffb52d079109dca5664cce6f317373782/login.SkyPe.com/en/cgi-bin/verification/login/70ffb52d079109dca5664cce6f317373/index.php?cmd=_profile-ach&outdated_page_tmpl=p/gen/failed-to-load&nav=0.5.1&login_access=1322408526", 1),
    ("www.dghjdgf.com/paypal.co.uk/cycgi-bin/webscrcmd=_home-customer&nav=1/loading.php", 1),
    ("serviciosbys.com/paypal.cgi.bin.get-into.herf.secure.dispatch35463256rzr321654641dsf654321874/href/href/href/secure/center/update/limit/seccure/4d7a1ff5c55825a2e632a679c2fd5353/", 1),
    ("mail.printakid.com/www.online.americanexpress.com/index.html", 1),
    ("thewhiskeydregs.com/wp-content/themes/widescreen/includes/temp/promocoessmiles/?84784787824HDJNDJDSJSHD//2724782784/", 1),
    ("smilesvoegol.servebbs.org/voegol.php", 1),
    ("premierpaymentprocessing.com/includes/boleto-2via-07-2012.php", 1),
    ("myxxxcollection.com/v1/js/jih321/bpd.com.do/do/l.popular.php", 1),
    ("super1000.info/docs", 1),
    ("horizonsgallery.com/js/bin/ssl1/_id/www.paypal.com/fr/cgi-bin/webscr/cmd=_registration-run/login.php?cmd=_login-run&amp;dispatch=1471c4bdb044ae2be9e2fc3ec514b88b1471c4bdb044ae2be9e2fc3ec514b88b", 1),
]


def test_url(url: str, expected: int, index: int) -> dict:
    """
    Test a single URL against the API
    
    Args:
        url: The URL to test
        expected: Expected label (0=safe, 1=not safe)
        index: URL index number
        
    Returns:
        Dictionary with test results
    """
    try:
        response = requests.post(
            API_URL,
            json={"url": url},
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            
            # Determine if prediction matches expected
            ml_pred = data.get("ml_prediction", "").lower()
            predicted_label = 1 if ml_pred == "not safe" else 0
            
            is_correct = predicted_label == expected
            
            # Extract flagged checks
            flagged_checks = []
            for check in data.get("checks", []):
                if check.get("flagged"):
                    flagged_checks.append({
                        "name": check.get("name"),
                        "reason": check.get("reason")
                    })
            
            return {
                "index": index,
                "url": url,
                "expected": "Not Safe" if expected == 1 else "Safe",
                "predicted": ml_pred.title(),
                "risk_score": data.get("risk_score", "N/A"),
                "risk_level": data.get("risk_level", "N/A"),
                "confidence": data.get("ml_confidence", 0),
                "is_correct": is_correct,
                "status": "✅" if is_correct else "❌",
                "flagged_checks": flagged_checks,
                "error": None
            }
        else:
            return {
                "index": index,
                "url": url,
                "expected": "Not Safe" if expected == 1 else "Safe",
                "error": f"HTTP {response.status_code}: {response.text[:100]}"
            }
            
    except requests.exceptions.ConnectionError:
        return {
            "index": index,
            "url": url,
            "expected": "Not Safe" if expected == 1 else "Safe",
            "error": "Connection Error - Is the API server running?"
        }
    except Exception as e:
        return {
            "index": index,
            "url": url,
            "expected": "Not Safe" if expected == 1 else "Safe",
            "error": str(e)
        }


def print_header():
    """Print test header"""
    print("=" * 100)
    print(" " * 30 + "URL VALIDATION TEST")
    print("=" * 100)
    print(f"Testing {len(TEST_URLS)} URLs against API: {API_URL}")
    print("=" * 100)
    print()


def print_result(result: dict):
    """Print individual test result"""
    if result.get("error"):
        print(f"{result['status'] if 'status' in result else '❌'} URL {result['index']+1}/20")
        print(f"   URL: {result['url'][:80]}...")
        print(f"   Expected: {result['expected']}")
        print(f"   ERROR: {result['error']}")
    else:
        print(f"{result['status']} URL {result['index']+1}/20")
        print(f"   URL: {result['url'][:80]}...")
        print(f"   Expected: {result['expected']} | Predicted: {result['predicted']}")
        print(f"   Risk Score: {result['risk_score']} | Level: {result['risk_level']}")
        print(f"   ML Confidence: {result['confidence']*100:.1f}%")
        
        # Show flagged checks if any
        flagged = result.get('flagged_checks', [])
        if flagged:
            print(f"   ⚠️  Flagged Checks ({len(flagged)}):")
            for check in flagged:
                print(f"      • {check['name']}: {check['reason']}")
    print()


def print_summary(results: List[dict]):
    """Print test summary"""
    total = len(results)
    correct = sum(1 for r in results if not r.get("error") and r.get("is_correct"))
    errors = sum(1 for r in results if r.get("error"))
    accuracy = (correct / (total - errors) * 100) if (total - errors) > 0 else 0
    
    print("=" * 100)
    print(" " * 35 + "TEST SUMMARY")
    print("=" * 100)
    print(f"Total URLs Tested: {total}")
    print(f"Correct Predictions: {correct}")
    print(f"Incorrect Predictions: {total - errors - correct}")
    print(f"Errors: {errors}")
    print(f"Accuracy: {accuracy:.1f}%")
    print("=" * 100)


def main():
    """Main test execution"""
    print_header()
    
    results = []
    
    for i, (url, expected) in enumerate(TEST_URLS):
        result = test_url(url, expected, i)
        results.append(result)
        print_result(result)
    
    print_summary(results)


if __name__ == "__main__":
    main()
