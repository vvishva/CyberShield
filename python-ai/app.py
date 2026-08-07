import os
import joblib
from flask import Flask, request, jsonify
from flask_cors import CORS
from train_model import extract_features

app = Flask(__name__)
CORS(app)

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'phishing_model.pkl')

model = None
if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
        print("[CyberShield AI Microservice] Loaded Scikit-Learn Model successfully.")
    except Exception as e:
        print(f"[CyberShield AI Warning] Failed loading model: {e}")

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ONLINE',
        'service': 'CyberShield Python AI Microservice',
        'modelLoaded': model is not None
    })

@app.route('/predict-url', methods=['POST'])
def predict_url():
    data = request.get_json() or {}
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    features = extract_features(url)
    
    if model is not None:
        try:
            proba = model.predict_proba([features])[0] # [p_safe, p_phish]
            phish_prob = float(proba[1])
            risk_percentage = int(round(phish_prob * 100))
            
            if risk_percentage >= 65:
                status = 'Phishing'
            elif risk_percentage >= 35:
                status = 'Suspicious'
            else:
                status = 'Safe'

            confidence_score = int(round(max(proba) * 100))

            return jsonify({
                'url': url,
                'status': status,
                'riskPercentage': risk_percentage,
                'confidenceScore': confidence_score,
                'features': {
                    'urlLength': features[0],
                    'hostnameLength': features[1],
                    'isHttps': features[2],
                    'hasIpAddress': features[3],
                    'dotCount': features[4],
                    'hyphenCount': features[5],
                    'atSymbolCount': features[6],
                    'subdomainCount': features[7],
                    'keywordMatches': features[8]
                },
                'recommendations': [
                    'Do not enter credentials on suspicious sites.',
                    'Check SSL certificate details.',
                    'Verify URL domain spelling.'
                ]
            })
        except Exception as e:
            print(f"[AI Predict Error] {e}")

    # Fallback response
    return jsonify({
        'url': url,
        'status': 'Suspicious' if features[0] > 70 or not features[2] else 'Safe',
        'riskPercentage': 45 if not features[2] else 10,
        'confidenceScore': 90,
        'features': {
            'urlLength': features[0],
            'isHttps': features[2]
        }
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    debug_mode = os.environ.get('NODE_ENV', 'development') != 'production'
    print(f"[CyberShield AI Microservice] Launching on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
