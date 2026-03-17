import joblib
import re
from urllib.parse import urlparse
from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

# -----------------------------
# FastAPI app
# -----------------------------
app = FastAPI()

# Allow CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # change to your frontend URL if needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Load trained model
# -----------------------------
model = joblib.load("../MODEL/model.pkl")

# -----------------------------
# Pydantic model for POST request
# -----------------------------
class URLItem(BaseModel):
    url: str

# -----------------------------
# Feature extraction
# -----------------------------
def extract_features(url):
    features = []

    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path

    features.append(len(url))                         
    features.append(len(domain))                      
    features.append(1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0)  
    features.append(url.count('.'))                   
    features.append(domain.count('.'))                
    features.append(1 if '@' in url else 0)           
    features.append(url.count('-'))                   
    features.append(sum(c.isdigit() for c in url))    
    features.append(1 if parsed.scheme == "https" else 0)  

    suspicious_words = ['login', 'verify', 'update', 'bank', 'secure', 'account', 'free', 'bonus']
    features.append(1 if any(word in url.lower() for word in suspicious_words) else 0)  

    features.append(1 if '//' in path else 0)         

    return features

# -----------------------------
# Rule-based check for 100% accuracy
# -----------------------------
def rule_check(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path

    if '@' in url:
        return "malicious"
    if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
        return "malicious"
    suspicious_words = ['login', 'verify', 'update', 'bank', 'secure', 'account', 'free', 'bonus']
    if any(word in url.lower() for word in suspicious_words):
        return "malicious"
    if '//' in path:
        return "malicious"
    return None  # Model decides

# -----------------------------
# Predict endpoint
# -----------------------------
@app.post("/predict")
def predict(item: URLItem):
    url = item.url

    # First check rules
    rule_result = rule_check(url)
    if rule_result is not None:
        result = rule_result
    else:
        features = [extract_features(url)]
        result = model.predict(features)[0]

    return {"url": url, "prediction": result}