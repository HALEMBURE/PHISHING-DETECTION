import pandas as pd
import re
import joblib
import os
from urllib.parse import urlparse
from sklearn.utils import resample
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, precision_recall_fscore_support

# -----------------------------
# Load dataset
# -----------------------------
BASE_DIR = os.path.dirname(__file__)
DATASET_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "DATA", "malicious_phish.csv"))
MODEL_OUT_PATH = os.path.abspath(os.path.join(BASE_DIR, "model.pkl"))

df = pd.read_csv(DATASET_PATH)

# -----------------------------
# Fix labels
# -----------------------------
malicious_types = ['phishing', 'malware', 'defacement']
df['label'] = df['type'].apply(lambda x: 'malicious' if x in malicious_types else 'benign')

print("Original counts:")
print(df['label'].value_counts())

# -----------------------------
# Feature extraction
# -----------------------------
def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path

    features = [
        len(url),
        len(domain),
        1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0,
        url.count('.'),
        domain.count('.'),
        1 if '@' in url else 0,
        url.count('-'),
        sum(c.isdigit() for c in url),
        1 if parsed.scheme == "https" else 0,
        1 if any(word in url.lower() for word in
                 ['login','verify','update','bank','secure','free','bonus']) else 0,  # removed 'account'
        1 if '//' in path else 0
    ]
    return features

# -----------------------------
# Prepare data
# -----------------------------
X = df['url'].apply(extract_features).tolist()
y = df['label']

# -----------------------------
# Train-test split
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# -----------------------------
# Balance only training split
# -----------------------------
train_df = pd.DataFrame({"features": X_train, "label": y_train})
train_benign = train_df[train_df["label"] == "benign"]
train_malicious = train_df[train_df["label"] == "malicious"]

train_malicious_up = resample(
    train_malicious,
    replace=True,
    n_samples=len(train_benign),
    random_state=42
)

train_balanced = pd.concat([train_benign, train_malicious_up]).sample(frac=1, random_state=42)
X_train_balanced = train_balanced["features"].tolist()
y_train_balanced = train_balanced["label"]

print("\nBalanced train counts:")
print(train_balanced["label"].value_counts())

# -----------------------------
# Train model
# -----------------------------
model = RandomForestClassifier(
    n_estimators=500,
    max_depth=None,
    min_samples_split=2,
    class_weight="balanced",
    random_state=42,
    n_jobs=1
)

print("\nTraining model...")
model.fit(X_train_balanced, y_train_balanced)

# -----------------------------
# Evaluation
# -----------------------------
y_pred = model.predict(X_test)
print("\nAccuracy:", accuracy_score(y_test, y_pred))
print("\n", classification_report(y_test, y_pred))
prec, rec, f1, _ = precision_recall_fscore_support(
    y_test,
    y_pred,
    average="binary",
    pos_label="malicious",
    zero_division=0,
)
print(f"Malicious precision: {prec:.4f}")
print(f"Malicious recall: {rec:.4f}")
print(f"Malicious F1: {f1:.4f}")

# -----------------------------
# Save final model
# -----------------------------
joblib.dump(model, MODEL_OUT_PATH)
print("\nFINAL MODEL TRAINED & SAVED")
