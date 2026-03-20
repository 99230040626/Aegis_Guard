"""
Aegis Guard - ML Prediction Script
Loads the trained Random Forest model and predicts whether a URL is
safe, warning, or malicious. Returns a JSON result to stdout so the
Node.js backend can parse it via child_process.execFile.

Usage:
    python3 predict.py <url>

Output (JSON):
    {
        "url":        "<url>",
        "risk_score": <int 0-100>,
        "status":     "safe" | "warning" | "malicious",
        "features":   { "url_length": int, "special_count": int, "keyword_count": int }
    }
"""

import os
import sys
import json
import joblib
import numpy as np

# ---------------------------------------------------------------------------
# Feature configuration (must stay in sync with train.py)
# ---------------------------------------------------------------------------

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "update", "secure", "banking",
    "paypal", "password", "credential", "confirm", "wallet", "free", "prize",
    "winner", "urgent", "click", "limited", "offer", "suspend", "unusual",
    "activity", "apple", "amazon", "microsoft", "netflix", "ebay", "bit.ly",
    "tinyurl", "goo.gl",
]

SPECIAL_CHARS = ["@", "-", "_", ".", "?", "=", "&", "%", "#", "//"]

# Risk score thresholds mapped to class probabilities
# class 0 = safe, class 1 = warning, class 2 = malicious
STATUS_SAFE = "safe"
STATUS_WARNING = "warning"
STATUS_MALICIOUS = "malicious"


def extract_features(url: str) -> list:
    """
    Extract numerical features from a URL.
    Returns [url_length, special_count, keyword_count].
    """
    url_lower = url.lower()
    url_length = len(url)
    special_count = sum(url.count(c) for c in SPECIAL_CHARS)
    keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    return [url_length, special_count, keyword_count]


def load_model(model_path: str = None):
    """
    Load the trained classifier from disk.
    Raises a RuntimeError with clear instructions if model.pkl is missing.
    Run `python3 train.py` once to generate it.
    """
    if model_path is None:
        model_path = os.path.join(os.path.dirname(__file__), "model.pkl")

    if not os.path.exists(model_path):
        raise RuntimeError(
            f"Model file not found: {model_path}\n"
            "Please train the model first by running:\n"
            "    python3 train.py"
        )

    return joblib.load(model_path)


def predict(url: str) -> dict:
    """
    Run the ML model on the given URL.

    Returns a dict with url, risk_score (0-100), status, and extracted features.
    """
    clf = load_model()
    features = extract_features(url)
    X = np.array([features])

    # Get class probabilities: [P(safe), P(warning), P(malicious)]
    proba = clf.predict_proba(X)[0]

    # Map to 0-100 risk score:
    # risk_score = weighted average: warning contributes 50%, malicious 100%
    risk_score = int(round((proba[1] * 50 + proba[2] * 100)))
    risk_score = max(0, min(100, risk_score))

    # Determine status
    if risk_score < 30:
        status = STATUS_SAFE
    elif risk_score < 65:
        status = STATUS_WARNING
    else:
        status = STATUS_MALICIOUS

    return {
        "url": url,
        "risk_score": risk_score,
        "status": status,
        "features": {
            "url_length": features[0],
            "special_count": features[1],
            "keyword_count": features[2],
        },
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No URL provided. Usage: python3 predict.py <url>"}))
        sys.exit(1)

    url = sys.argv[1]
    result = predict(url)
    print(json.dumps(result))
