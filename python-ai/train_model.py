import os
import re
import numpy as np
import pandas as pd
import joblib
import requests
import zipfile
import io
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# Real dataset URLs
PHISHTANK_CSV_URL = 'http://data.phishtank.com/data/online-valid.csv'
OPENPHISH_URL = 'https://openphish.com/feed.txt'
ALEXA_TOP_URL = 'http://s3.amazonaws.com/alexa-static/top-1m.csv.zip'
TRANCO_TOP_URL = 'https://tranco-list.eu/top-1m.csv.zip'

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
                'apple', 'google', 'signin', 'confirm', 'password', 'token', 'crypto',
                'wallet', 'bank', 'credit', 'card', 'ssn', 'social', 'security',
                'admin', 'panel', 'dashboard', 'confirm', 'validate', 'authenticate']
    keyword_count = sum(1 for kw in keywords if kw in url.lower())

    return [url_length, hostname_length, is_https, has_ip, dot_count, hyphen_count, at_count, subdomain_count, keyword_count]

def download_phishtank():
    """Download and parse PhishTank dataset."""
    print("[CyberShield AI] Downloading PhishTank dataset...")
    try:
        response = requests.get(PHISHTANK_CSV_URL, timeout=60)
        response.raise_for_status()
        df = pd.read_csv(io.StringIO(response.text))
        # Filter for online and valid phishing URLs
        df = df[(df['online'] == 'yes') & (df['verified'] == 'yes')]
        urls = df['url'].tolist()
        print(f"[CyberShield AI] Loaded {len(urls)} PhishTank URLs")
        return urls
    except Exception as e:
        print(f"[CyberShield AI] Warning: Failed to download PhishTank: {e}")
        return []

def download_openphish():
    """Download and parse OpenPhish dataset."""
    print("[CyberShield AI] Downloading OpenPhish dataset...")
    try:
        response = requests.get(OPENPHISH_URL, timeout=30)
        response.raise_for_status()
        urls = [line.strip() for line in response.text.split('\n') if line.strip()]
        print(f"[CyberShield AI] Loaded {len(urls)} OpenPhish URLs")
        return urls
    except Exception as e:
        print(f"[CyberShield AI] Warning: Failed to download OpenPhish: {e}")
        return []

def download_tranco():
    """Download and parse Tranco top domains (safe URLs)."""
    print("[CyberShield AI] Downloading Tranco top domains...")
    try:
        response = requests.get(TRANCO_TOP_URL, timeout=60)
        response.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            with z.open(z.namelist()[0]) as f:
                df = pd.read_csv(f, header=None, names=['rank', 'domain'])
        urls = ['https://' + d for d in df['domain'].tolist()]
        print(f"[CyberShield AI] Loaded {len(urls)} Tranco safe domains")
        return urls
    except Exception as e:
        print(f"[CyberShield AI] Warning: Failed to download Tranco: {e}")
        return []

def download_alexa():
    """Download and parse Alexa top domains (safe URLs)."""
    print("[CyberShield AI] Downloading Alexa top domains...")
    try:
        response = requests.get(ALEXA_TOP_URL, timeout=60)
        response.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            with z.open(z.namelist()[0]) as f:
                df = pd.read_csv(f, header=None, names=['rank', 'domain'])
        urls = ['https://' + d for d in df['domain'].tolist()]
        print(f"[CyberShield AI] Loaded {len(urls)} Alexa safe domains")
        return urls
    except Exception as e:
        print(f"[CyberShield AI] Warning: Failed to download Alexa: {e}")
        return []

def generate_realistic_dataset(max_phish=50000, max_safe=50000):
    """
    Generates dataset using real phishing URLs and legitimate top domains.
    Falls back to synthetic data if downloads fail.
    """
    print("[CyberShield AI] Building training dataset from real sources...")
    
    # Try to download real data
    phish_urls = []
    safe_urls = []
    
    phish_urls.extend(download_phishtank())
    phish_urls.extend(download_openphish())
    
    safe_urls.extend(download_tranco())
    if not safe_urls:
        safe_urls.extend(download_alexa())
    
    # Fallback to synthetic if downloads failed
    if not phish_urls:
        print("[CyberShield AI] Using synthetic phishing URLs as fallback")
        phish_templates = [
            'http://login-verify-paypal-account-update.com/auth',
            'http://192.168.1.100/secure-banking/verify.php',
            'http://appleid-login-verification-support.net/confirm',
            'http://secure-crypto-wallet-bonus-free.xyz/claim',
            'http://account-update-google-security.info/login.html',
            'http://bankofamerica-security-alert.net/verify',
            'http://microsoft-office365-login.phishersite.com/signin',
            'http://amazon-account-update-required.xyz/confirm',
            'http://paypal-security-center-login.tk/auth',
            'http://netflix-billing-update-required.ml/verify'
        ]
        for i in range(min(max_phish, 10000)):
            p = phish_templates[i % len(phish_templates)]
            phish_urls.append(f"{p}?token={i}&user=verify")
    
    if not safe_urls:
        print("[CyberShield AI] Using synthetic safe URLs as fallback")
        safe_domains = ['google.com', 'github.com', 'microsoft.com', 'wikipedia.org', 
                        'amazon.com', 'stackoverflow.com', 'medium.com', 'nytimes.com',
                        'youtube.com', 'facebook.com', 'twitter.com', 'linkedin.com',
                        'reddit.com', 'netflix.com', 'spotify.com', 'adobe.com',
                        'apple.com', 'cloudflare.com', 'mozilla.org', 'ubuntu.com']
        for i in range(min(max_safe, 20000)):
            d = safe_domains[i % len(safe_domains)]
            safe_urls.append(f"https://www.{d}/path/to/page_{i}")
    
    # Limit dataset size
    phish_urls = phish_urls[:max_phish]
    safe_urls = safe_urls[:max_safe]
    
    print(f"[CyberShield AI] Final dataset: {len(phish_urls)} phishing, {len(safe_urls)} safe")
    
    data = []
    for url in safe_urls:
        feat = extract_features(url)
        data.append(feat + [0])  # 0 = Safe
    
    for url in phish_urls:
        feat = extract_features(url)
        data.append(feat + [1])  # 1 = Phishing
    
    columns = ['url_length', 'hostname_length', 'is_https', 'has_ip', 'dot_count', 
               'hyphen_count', 'at_count', 'subdomain_count', 'keyword_count', 'label']
    return pd.DataFrame(data, columns=columns)

def train_and_save_model():
    print("[CyberShield AI] Training URL Phishing Classification Model...")
    df = generate_realistic_dataset(50000, 50000)
    
    # Balance classes if needed
    safe_count = len(df[df['label'] == 0])
    phish_count = len(df[df['label'] == 1])
    print(f"[CyberShield AI] Class distribution: Safe={safe_count}, Phishing={phish_count}")
    
    X = df.drop('label', axis=1)
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'
    )
    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)
    print(f"[CyberShield AI] Model Training Completed. Accuracy: {acc * 100:.2f}%")
    print(f"[CyberShield AI] Classification Report:\n{classification_report(y_test, preds)}")

    # Feature importance
    feature_names = X.columns
    importances = model.feature_importances_
    for name, imp in sorted(zip(feature_names, importances), key=lambda x: -x[1]):
        print(f"[CyberShield AI] Feature Importance: {name} = {imp:.4f}")

    model_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(model_dir, 'phishing_model.pkl')
    joblib.dump(model, model_path)
    print(f"[CyberShield AI] Saved trained model to {model_path}")

if __name__ == '__main__':
    train_and_save_model()