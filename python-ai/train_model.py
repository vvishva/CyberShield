import os
import re
import numpy as np
import pandas as pd
import joblib
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

def extract_features(url):
    """
    Extracts lexical features from a URL string for Scikit-learn Machine Learning.
    Returns numpy array of feature values:
    [url_length, hostname_length, is_https, has_ip, dot_count, hyphen_count, at_count, subdomain_count, keyword_count]
    """
    url = str(url).strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or url
    except Exception:
        hostname = url

    url_length = len(url)
    hostname_length = len(hostname)
    is_https = 1 if url.startswith('https://') else 0
    has_ip = 1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', hostname) else 0
    dot_count = url.count('.')
    hyphen_count = hostname.count('-')
    at_count = url.count('@')
    subdomain_count = max(0, len(hostname.split('.')) - 2)

    keywords = ['login', 'verify', 'update', 'account', 'banking', 'secure', 'paypal',
                'apple', 'google', 'signin', 'confirm', 'password', 'token', 'crypto']
    keyword_count = sum(1 for kw in keywords if kw in url.lower())

    return [url_length, hostname_length, is_https, has_ip, dot_count, hyphen_count, at_count, subdomain_count, keyword_count]

def generate_synthetic_dataset(num_samples=1000):
    """
    Generates synthetic phishing and safe URL dataset for initial model training.
    """
    data = []
    
    # Safe domain templates
    safe_domains = ['google.com', 'github.com', 'microsoft.com', 'wikipedia.org', 
                    'amazon.com', 'stackoverflow.com', 'medium.com', 'nytimes.com']
    
    # Phishing domain templates
    phish_templates = [
        'http://login-verify-paypal-account-update.com/auth',
        'http://192.168.1.100/secure-banking/verify.php',
        'http://appleid-login-verification-support.net/confirm',
        'http://secure-crypto-wallet-bonus-free.xyz/claim',
        'http://account-update-google-security.info/login.html'
    ]

    for i in range(num_samples // 2):
        d = safe_domains[i % len(safe_domains)]
        url = f"https://www.{d}/path/to/page_{i}"
        feat = extract_features(url)
        data.append(feat + [0]) # 0 = Safe

    for i in range(num_samples // 2):
        p = phish_templates[i % len(phish_templates)]
        url = f"{p}?token={i}&user=verify"
        feat = extract_features(url)
        data.append(feat + [1]) # 1 = Phishing

    columns = ['url_length', 'hostname_length', 'is_https', 'has_ip', 'dot_count', 
               'hyphen_count', 'at_count', 'subdomain_count', 'keyword_count', 'label']
    return pd.DataFrame(data, columns=columns)

def train_and_save_model():
    print("[CyberShield AI] Training URL Phishing Classification Model...")
    df = generate_synthetic_dataset(1500)
    
    X = df.drop('label', axis=1)
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)
    print(f"[CyberShield AI] Model Training Completed. Accuracy: {acc * 100:.2f}%")

    model_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(model_dir, 'phishing_model.pkl')
    joblib.dump(model, model_path)
    print(f"[CyberShield AI] Saved trained model to {model_path}")

if __name__ == '__main__':
    train_and_save_model()
