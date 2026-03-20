"""
Aegis Guard - ML Model Training Script
Trains a Random Forest classifier for phishing URL detection.
Features: URL length, special character count, suspicious keyword presence.
The trained model is saved to model.pkl for use by predict.py.
"""

import os
import sys
import json
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# ---------------------------------------------------------------------------
# Feature extraction helpers (must stay in sync with predict.py)
# ---------------------------------------------------------------------------

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "update", "secure", "banking",
    "paypal", "password", "credential", "confirm", "wallet", "free", "prize",
    "winner", "urgent", "click", "limited", "offer", "suspend", "unusual",
    "activity", "apple", "amazon", "microsoft", "netflix", "ebay", "bit.ly",
    "tinyurl", "goo.gl",
]

SPECIAL_CHARS = ["@", "-", "_", ".", "?", "=", "&", "%", "#", "//"]


def extract_features(url: str) -> list:
    """
    Extract numerical features from a URL.

    Returns a list of three features:
    1. url_length      – total character count of the URL
    2. special_count   – number of special / suspicious characters
    3. keyword_count   – number of suspicious keywords found in the URL
    """
    url_lower = url.lower()
    url_length = len(url)
    special_count = sum(url.count(c) for c in SPECIAL_CHARS)
    keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    return [url_length, special_count, keyword_count]


# ---------------------------------------------------------------------------
# Synthetic training data
# ---------------------------------------------------------------------------

# Each entry: (url, label)  label: 0 = safe, 1 = warning, 2 = malicious
TRAINING_URLS = [
    # Safe URLs
    ("https://www.google.com", 0),
    ("https://www.github.com", 0),
    ("https://www.wikipedia.org", 0),
    ("https://www.stackoverflow.com/questions", 0),
    ("https://www.python.org/docs", 0),
    ("https://www.mozilla.org", 0),
    ("https://developer.mozilla.org/en-US/docs", 0),
    ("https://www.youtube.com/watch", 0),
    ("https://www.reddit.com/r/programming", 0),
    ("https://www.apple.com/support", 0),
    ("https://www.amazon.com/dp/product", 0),
    ("https://docs.python.org/3/library", 0),
    ("https://www.npmjs.com/package/express", 0),
    ("https://en.wikipedia.org/wiki/Machine_learning", 0),
    ("https://www.bbc.com/news", 0),
    ("https://www.nytimes.com/section/technology", 0),
    ("https://www.cloudflare.com/learning", 0),
    ("https://www.w3schools.com/html", 0),
    ("https://www.linkedin.com/in/user", 0),
    ("https://www.twitter.com/home", 0),
    # Warning URLs (somewhat suspicious)
    ("http://login.example-bank.com/user/verify", 1),
    ("http://update-account.info/signin?ref=email", 1),
    ("https://secure-paypal.info/account/login", 1),
    ("http://amazon-security-alert.com/verify", 1),
    ("http://microsoft-support-center.net/update", 1),
    ("http://apple-id-verification.com/confirm", 1),
    ("https://netflix-billing-update.net/account", 1),
    ("http://ebay-seller-alert.com/login?token=abc", 1),
    ("http://free-prize-winner.com/claim?id=12345", 1),
    ("http://urgent-account-suspend.info/secure", 1),
    ("https://bank-of-america-signin.net/login", 1),
    ("http://paypal-secure-update.biz/wallet/confirm", 1),
    ("https://googleaccounts-recovery.com/signin", 1),
    ("http://instagram-verify-account.net/confirm", 1),
    ("https://apple-unusual-activity.com/secure", 1),
    # Malicious URLs (clearly phishing)
    ("http://192.168.1.1/login.php?user=admin&pass=verify&token=xyz", 2),
    ("http://paypa1-secure-login.tk/account/confirm?session=abc123&verify=true", 2),
    ("http://www.g00gle-signin.cf/login?redirect=https://accounts.google.com&credential=steal", 2),
    ("http://amaz0n-prize-free-winner.ml/claim?id=winner123&urgent=yes", 2),
    ("http://bit.ly/3xYzAbc-limited-offer-free-prize-click-here", 2),
    ("https://micro50ft-account-unusual-activity-verify-now.tk/signin?token=abc&redirect=steal", 2),
    ("http://tinyurl.com/suspicious-link-free-iphone-winner-claim-now", 2),
    ("http://appleid-account-suspended-verify.gq/login?credential=confirm&password=reset", 2),
    ("http://bankofamerica-secure-login-verify.cf/account?session=steal&confirm=yes", 2),
    ("http://netfl1x-billing-update-immediately.tk/payment?card=enter&credential=verify", 2),
    ("http://instagram-account-disabled-verify.ml/login?token=abc&password=confirm", 2),
    ("http://irs-tax-refund-free-claim-now.cf/refund?ssn=enter&credential=verify", 2),
    ("http://amazon-free-giftcard-winner-claim.gq/prize?winner=you&urgent=yes&limited=offer", 2),
    ("http://paypal-wallet-unusual-activity-login.tk/secure?verify=now&password=update", 2),
    ("http://ebay-seller-account-suspend-verify.ml/signin?credential=confirm&secure=update", 2),
]


def build_dataset():
    """Convert training URLs into feature matrix X and label vector y."""
    X, y = [], []
    for url, label in TRAINING_URLS:
        X.append(extract_features(url))
        y.append(label)
    return np.array(X), np.array(y)


# ---------------------------------------------------------------------------
# Train and save model
# ---------------------------------------------------------------------------

def train_model(output_path: str = None):
    """Train the Random Forest classifier and persist it to disk."""
    if output_path is None:
        output_path = os.path.join(os.path.dirname(__file__), "model.pkl")

    print("[Aegis Guard] Extracting features from training URLs...")
    X, y = build_dataset()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("[Aegis Guard] Training Random Forest classifier...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight="balanced",
    )
    clf.fit(X_train, y_train)

    # Evaluate
    y_pred = clf.predict(X_test)
    print("\n[Aegis Guard] Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["safe", "warning", "malicious"]))

    # Persist model
    joblib.dump(clf, output_path)
    print(f"[Aegis Guard] Model saved to: {output_path}")
    return clf


if __name__ == "__main__":
    train_model()
