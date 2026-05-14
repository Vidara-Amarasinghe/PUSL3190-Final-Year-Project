import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
import os

MODEL_FILE  = "/home/student/dns-anomaly/isolation_forest.pkl"
SCALER_FILE = "/home/student/dns-anomaly/scaler.pkl"

def train_model():
    print("Training model with curated legitimate baseline data...")

    # ── Legitimate traffic patterns only ──
    # [entropy, depth, length, query_count]
    legitimate = [
        # Core - mydns.test (depth 2, length 10)
        [2.92, 2, 10, 1], [2.92, 2, 10, 2],
        [2.92, 2, 10, 3], [2.92, 2, 10, 4],
        # Web - www, web (depth 3, length 14)
        [3.04, 3, 14, 1], [3.04, 3, 14, 2],
        [2.95, 3, 14, 1], [2.95, 3, 14, 2],
        # Mail records (depth 3, length 14-19)
        [3.37, 3, 15, 1], [3.37, 3, 15, 2],
        [3.18, 3, 15, 1], [3.18, 3, 15, 2],
        [3.17, 3, 15, 1], [3.17, 3, 15, 2],
        [3.46, 3, 19, 1], [3.46, 3, 19, 2],
        # Remote access
        [3.18, 3, 14, 1], [3.18, 3, 14, 2],
        [3.24, 3, 14, 1], [3.24, 3, 14, 2],
        [3.04, 3, 14, 1], [3.04, 3, 14, 2],
        [3.32, 3, 17, 1], [3.32, 3, 17, 2],
        # Application servers
        [3.38, 3, 14, 1], [3.38, 3, 14, 2],
        [3.09, 3, 14, 1], [3.09, 3, 14, 2],
        [3.46, 3, 17, 1], [3.46, 3, 17, 2],
        [3.52, 3, 19, 1], [3.52, 3, 19, 2],
        # Development
        [3.09, 3, 14, 1], [3.09, 3, 14, 2],
        [3.17, 3, 15, 1], [3.17, 3, 15, 2],
        [3.46, 3, 19, 1], [3.46, 3, 19, 2],
        [3.00, 3, 13, 1], [3.00, 3, 13, 2],
        # Database
        [3.00, 3, 13, 1], [3.00, 3, 13, 2],
        [3.46, 3, 19, 1], [3.46, 3, 19, 2],
        [3.17, 3, 16, 1], [3.17, 3, 16, 2],
        # Infrastructure
        [3.17, 3, 16, 1], [3.17, 3, 16, 2],
        [3.46, 3, 18, 1], [3.46, 3, 18, 2],
        [3.24, 3, 17, 1], [3.24, 3, 17, 2],
        [3.17, 3, 18, 1], [3.17, 3, 18, 2],
        # Business
        [3.32, 3, 15, 1], [3.32, 3, 15, 2],
        [3.24, 3, 16, 1], [3.24, 3, 16, 2],
        [3.17, 3, 15, 1], [3.17, 3, 15, 2],
        [3.09, 3, 15, 1], [3.09, 3, 15, 2],
        [3.04, 3, 14, 1], [3.04, 3, 14, 2],
        # Security
        [3.17, 3, 15, 1], [3.17, 3, 15, 2],
        [3.17, 3, 16, 1], [3.17, 3, 16, 2],
        # Slight variations
        [2.90, 2, 10, 1], [3.00, 3, 14, 2],
        [3.10, 3, 15, 1], [2.85, 2, 11, 1],
        [3.20, 3, 16, 2], [2.95, 3, 13, 1],
        [3.05, 3, 15, 3], [3.15, 3, 17, 1],
        [3.25, 3, 18, 2], [3.35, 3, 19, 1],
    ]
    df = pd.DataFrame(legitimate,
                      columns=['entropy','depth',
                                'length','query_count'])

    print(f"Training on {len(df)} legitimate baseline samples...")

    scaler = StandardScaler()
    X = scaler.fit_transform(df)

    # contamination=0.05 means only 5% flagged as anomaly
    # This reduces false positives on legitimate traffic
    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42,
        max_samples='auto'
    )
    model.fit(X)

    with open(MODEL_FILE, 'wb') as f:
        pickle.dump(model, f)
    with open(SCALER_FILE, 'wb') as f:
        pickle.dump(scaler, f)

    print(f"Model saved to {MODEL_FILE}")
    print(f"Scaler saved to {SCALER_FILE}")
    return model, scaler

def load_model():
    if not os.path.exists(MODEL_FILE):
        print("No model found. Training new model...")
        return train_model()
    with open(MODEL_FILE, 'rb') as f:
        model = pickle.load(f)
    with open(SCALER_FILE, 'rb') as f:
        scaler = pickle.load(f)
    print("Model loaded successfully.")
    return model, scaler

def predict(model, scaler, entropy, depth, length, query_count):
    features = pd.DataFrame(
        [[entropy, depth, length, query_count]],
        columns=['entropy','depth','length','query_count'])
    scaled     = scaler.transform(features)
    score      = model.score_samples(scaled)[0]
    label      = model.predict(scaled)[0]
    is_anomaly = label == -1
    return is_anomaly, round(score, 4)

if __name__ == "__main__":
    model, scaler = train_model()
    if model:
        print("\n=== Testing ===")
        # Legitimate queries — should be False
        tests = [
            (2.95, 3, 14, 1,  "www.mydns.test A"),
            (2.92, 2, 10, 1,  "mydns.test MX"),
            (3.37, 3, 15, 1,  "mail.mydns.test A"),
            # Attacks — should be True
            (4.50, 3, 23, 25, "DGA domain"),
            (4.90, 3, 35, 40, "Tunneling domain"),
            (3.88, 3, 23, 30, "Random subdomain"),
            (3.28, 2, 14, 22, "Foreign domain burst"),
        ]
        for entropy, depth, length, count, label in tests:
            a, s = predict(model, scaler,
                           entropy, depth, length, count)
            status = "ATTACK" if a else "NORMAL"
            print(f"  {status:6} | score={s:7.4f} | {label}")
